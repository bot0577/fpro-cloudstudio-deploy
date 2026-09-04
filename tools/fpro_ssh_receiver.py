#!/usr/bin/env python3
"""One-shot SSH key delivery receiver for FPRO deployments.

The GUI bootstrap path generates the SSH key in the target container, then
sends one encrypted private/public-key bundle back to this workstation.  This
utility is deliberately scoped to that one-shot key bundle; it is not a
general-purpose file synchronizer.

It supports three operations:

* ``decrypt``: decrypt an already-downloaded ``.tar.gz.enc`` bundle locally;
* ``listen``: receive one authenticated HTTP POST on a loopback listener;
* ``proxy``: start ``listen`` and a temporary fpro TCP proxy, so a container
  can POST the encrypted bundle through an otherwise unused server port.

The receiver never sends the package password.  The password is entered on
this workstation, after the encrypted bytes have been received.  The HTTP
endpoint is one-shot, checks a random application token and SHA-256, validates
the private/public key pair, and writes the result atomically under ~/.ssh.
The temporary fpro proxy uses a separate ``--fpro-token-file`` credential for
the fpro server; it must never be confused with the one-shot HTTP token.
The packaged Windows app includes its crypto/key parser.  The standalone CLI
prefers the optional ``cryptography`` package and falls back to local
``openssl``/``ssh-keygen`` for legacy environments.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import math
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from getpass import getpass
from typing import NoReturn, Optional

try:
    from fpro_crypto import CryptoError, decrypt_file
except ImportError:  # pragma: no cover - package-relative import when embedded
    from .fpro_crypto import CryptoError, decrypt_file


MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_KEY_BYTES = 128 * 1024
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]{16,256}$")
KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/=_-]+$")
# An ASCII-only event line lets the Windows GUI detect readiness without
# depending on the active system code page.  The human-readable Chinese line
# is still emitted for standalone CLI users.
READY_MARKER = "__FPRO_EVENT_READY__"


class ReceiverError(RuntimeError):
    """A user-actionable validation or transport error."""


def decode_text(data: bytes, *, limit: int | None = None) -> str:
    """Decode subprocess/network text across UTF-8 and Windows code pages.

    The packaged GUI talks to a child process through a pipe.  On Windows a
    child launched without an explicit encoding can still use CP936, while
    Cloud Studio/fpro normally emits UTF-8.  Prefer UTF-8 and fall back to
    GB18030 when UTF-8 is invalid or would contain replacement characters.
    This keeps diagnostics readable without changing the on-disk protocol.
    """
    if limit is not None:
        data = data[:limit]
    if not data:
        return ""
    for encoding in ("utf-8", "gb18030"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\ufffd" not in text:
            return text
    return data.decode("utf-8", "replace")


def read_text_tail(path: pathlib.Path, max_bytes: int = 8192, max_chars: int = 2000) -> str:
    """Read a bounded, correctly decoded tail of a diagnostic log."""
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - max_bytes), os.SEEK_SET)
            data = stream.read(max_bytes)
    except OSError:
        return ""
    return decode_text(data)[-max_chars:]


def configure_stdio() -> None:
    """Use UTF-8 for piped worker output while preserving interactive consoles."""
    for stream in (getattr(sys, "stdout", None), getattr(sys, "stderr", None)):
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            if stream.isatty():
                continue
        except Exception:
            # A few embedded streams do not implement isatty reliably; they
            # are still safe to reconfigure for the worker protocol.
            pass
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def fail(message: str) -> NoReturn:
    raise ReceiverError(message)


def validate_token(token: str) -> str:
    token = token.strip()
    if not TOKEN_RE.fullmatch(token):
        fail("传输 token 格式无效；请使用至少 16 位随机字母数字 token。")
    return token


def validate_fpro_token(token: str) -> str:
    """Validate the fpro server credential without applying receiver-token rules."""
    token = token.strip()
    if not token or len(token) > 4096 or "\r" in token or "\n" in token:
        fail("fpro 认证 token 为空、过长或包含换行。")
    return token


def validate_key_name(name: str) -> str:
    if not KEY_NAME_RE.fullmatch(name):
        fail("SSH 密钥文件名只能包含字母、数字、点、下划线和连字符。")
    return name


def key_line(text: str) -> str:
    """Return the key type/blob, ignoring comments and trailing labels."""
    for raw in text.splitlines():
        parts = raw.strip().split()
        if len(parts) >= 2 and not parts[0].startswith("#"):
            return " ".join(parts[:2])
    return ""


def run_capture(command: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        fail(f"找不到依赖命令：{command[0]}。")
    except OSError as exc:
        fail(f"执行 {command[0]} 失败：{exc}")


def ensure_command(name: str) -> None:
    if shutil.which(name) is None:
        fail(f"找不到依赖命令：{name}。")


def ssh_fingerprint(public_text: str) -> str:
    """Return an OpenSSH-compatible SHA256 fingerprint.

    Prefer the bundled ``cryptography`` implementation so the Windows
    one-click executable does not require an independently installed
    ``ssh-keygen``.  Keep the command-line fallback for unusual legacy key
    formats and for the standalone CLI on minimal Python installations.
    """
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_ssh_public_key(public_text.encode("utf-8"))
        blob = key.public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        # OpenSSH's wire blob is the portion after the key type and before an
        # optional comment.  Re-parse the canonical serialized line so labels
        # in the incoming .pub file cannot affect the digest.
        parts = blob.split()
        if len(parts) < 2:
            raise ValueError("empty public key blob")
        digest = hashlib.sha256(base64.b64decode(parts[1])).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except Exception as python_error:
        if shutil.which("ssh-keygen") is None:
            fail(f"SSH 公钥无效或当前环境缺少密钥解析支持：{python_error}")
        result = run_capture(["ssh-keygen", "-lf", "-"], input_bytes=public_text.encode())
        if result.returncode != 0:
            detail = decode_text(result.stderr).strip()
            fail(f"SSH 公钥无效：{detail[:300]}")
        fields = decode_text(result.stdout).split()
        if len(fields) < 2:
            fail("ssh-keygen 没有返回公钥指纹。")
        return fields[1]


def derive_public(private_path: pathlib.Path, passphrase: str = "") -> str:
    try:
        from cryptography.hazmat.primitives import serialization

        private_data = private_path.read_bytes()
        password = passphrase.encode("utf-8") if passphrase else None
        key = serialization.load_ssh_private_key(private_data, password=password)
        public = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ).decode("utf-8", "replace").strip()
        if not key_line(public):
            raise ValueError("empty derived public key")
        return public + "\n"
    except Exception as python_error:
        if shutil.which("ssh-keygen") is None:
            fail(f"无法从 SSH 私钥导出公钥：{python_error}")
        # -P prevents ssh-keygen from opening an interactive prompt while the
        # receiver is running in an HTTP worker thread.
        result = run_capture(
            ["ssh-keygen", "-y", "-P", passphrase, "-f", str(private_path)]
        )
        if result.returncode != 0:
            detail = decode_text(result.stderr).strip()
            fail(f"无法从 SSH 私钥导出公钥：{detail[:300]}")
        public = decode_text(result.stdout).strip()
        if not key_line(public):
            fail("从 SSH 私钥导出的公钥为空。")
        return public + "\n"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def chmod_private(path: pathlib.Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass
    # chmod is meaningful on POSIX but only advisory on Windows.  Tighten the
    # ACL when icacls is available; failure is non-fatal because enterprise
    # Windows policies may intentionally manage ACLs centrally.
    if os.name == "nt" and shutil.which("icacls"):
        user = os.environ.get("USERNAME")
        if user:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


def chmod_public(path: pathlib.Path) -> None:
    try:
        path.chmod(0o644)
    except OSError:
        pass


def atomic_write(path: pathlib.Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary_path = pathlib.Path(temporary)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        if mode == 0o600:
            chmod_private(path)
        else:
            chmod_public(path)
    finally:
        try:
            temporary_path.unlink()
        except OSError:
            pass


def read_secret(args: argparse.Namespace, *, kind: str) -> str:
    file_arg = getattr(args, f"{kind}_file", None)
    stdin_arg = getattr(args, f"{kind}_stdin", False)
    env_arg = getattr(args, f"{kind}_env", None)
    direct_arg = getattr(args, kind, None)
    value = ""
    if file_arg:
        try:
            value = pathlib.Path(file_arg).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            fail(f"读取 {kind} 文件失败：{exc}")
    elif stdin_arg:
        value = sys.stdin.readline().rstrip("\r\n")
    elif env_arg:
        value = os.environ.get(env_arg, "")
    elif direct_arg:
        value = direct_arg
    else:
        if kind == "password":
            prompt = "解压密码: "
        elif kind == "fpro_token":
            prompt = "fpro 认证 token: "
        else:
            prompt = "传输 token: "
        value = getpass(prompt)
    if not value:
        fail(f"{kind} 不能为空。")
    return value


def package_password(args: argparse.Namespace) -> str:
    return read_secret(args, kind="password")


def key_passphrase(args: argparse.Namespace) -> Optional[str]:
    if getattr(args, "no_key_passphrase_prompt", False):
        return ""
    if getattr(args, "key_passphrase_file", None):
        try:
            return pathlib.Path(args.key_passphrase_file).read_text(
                encoding="utf-8"
            ).rstrip("\r\n")
        except OSError as exc:
            fail(f"读取 SSH 私钥口令文件失败：{exc}")
    if getattr(args, "key_passphrase_stdin", False):
        return sys.stdin.readline().rstrip("\r\n")
    return None


def toml_quote(value: str) -> str:
    return '"' + value.replace("\\", "/").replace('"', '\\"') + '"'


def parse_archive(
    tar_path: pathlib.Path,
    *,
    key_name_hint: Optional[str],
    expected_fingerprint: Optional[str],
    ssh_passphrase: Optional[str],
    prompt_for_key_passphrase: bool,
) -> tuple[str, bytes, bytes, str]:
    """Validate an archive and return (name, private, public, fingerprint)."""
    try:
        archive = tarfile.open(tar_path, mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        fail(f"解密后的 SSH 密钥包不是有效 tar.gz：{exc}")

    with archive:
        members = archive.getmembers()
        if not members:
            fail("SSH 密钥包为空。")
        files: dict[str, tarfile.TarInfo] = {}
        for member in members:
            # Do not extract links, device nodes, directories or path traversal
            # entries.  The exporter creates exactly two regular files.
            name = pathlib.PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or len(name.parts) != 1:
                fail("SSH 密钥包包含不安全的路径。")
            if not member.isfile() or member.size > MAX_KEY_BYTES:
                fail("SSH 密钥包包含非普通文件或文件过大。")
            files[name.name] = member

        if key_name_hint:
            key_name = validate_key_name(key_name_hint)
        else:
            candidates = [
                name
                for name in files
                if not name.endswith(".pub") and KEY_NAME_RE.fullmatch(name)
            ]
            if len(candidates) != 1:
                fail("无法从密钥包唯一确定 SSH 私钥文件名，请指定 --key-name。")
            key_name = candidates[0]

        expected_names = {key_name, f"{key_name}.pub"}
        if set(files) != expected_names:
            fail("SSH 密钥包必须只包含私钥及其 .pub 公钥文件。")

        private_member = archive.extractfile(files[key_name])
        public_member = archive.extractfile(files[f"{key_name}.pub"])
        if private_member is None or public_member is None:
            fail("读取 SSH 密钥包内容失败。")
        private_data = private_member.read(MAX_KEY_BYTES + 1)
        public_data = public_member.read(MAX_KEY_BYTES + 1)
        if len(private_data) > MAX_KEY_BYTES or len(public_data) > MAX_KEY_BYTES:
            fail("SSH 密钥文件超过大小限制。")

    public_text = public_data.decode("utf-8", "replace")
    public_key = key_line(public_text)
    if not public_key:
        fail("SSH 公钥文件格式无效。")
    fingerprint = ssh_fingerprint(public_text)
    if expected_fingerprint and fingerprint != expected_fingerprint:
        fail(
            f"收到的公钥指纹 {fingerprint} 与预期 {expected_fingerprint} 不一致。"
        )

    with tempfile.TemporaryDirectory(prefix="fpro-key-check-") as check_dir:
        private_path = pathlib.Path(check_dir) / key_name
        private_path.write_bytes(private_data)
        chmod_private(private_path)
        passphrase = ssh_passphrase
        try:
            derived = derive_public(private_path, passphrase or "")
        except ReceiverError:
            if passphrase is not None or not prompt_for_key_passphrase:
                raise
            passphrase = getpass("SSH 私钥本身的口令（无口令直接回车）: ")
            derived = derive_public(private_path, passphrase)
        if key_line(derived) != public_key:
            fail("SSH 私钥与 .pub 公钥不匹配。")

    return key_name, private_data, public_data, fingerprint


def decrypt_and_validate(
    encrypted_path: pathlib.Path,
    *,
    password: str,
    key_name_hint: Optional[str],
    expected_fingerprint: Optional[str],
    ssh_passphrase: Optional[str],
    prompt_for_key_passphrase: bool = True,
) -> tuple[str, bytes, bytes, str]:
    with tempfile.TemporaryDirectory(prefix="fpro-key-decrypt-") as work:
        tar_path = pathlib.Path(work) / "bundle.tar.gz"
        try:
            tar_path.write_bytes(decrypt_file(encrypted_path, password, max_bytes=MAX_BUNDLE_BYTES))
        except (CryptoError, OSError):
            fail("解密失败：密码错误或密钥包损坏。")
        return parse_archive(
            tar_path,
            key_name_hint=key_name_hint,
            expected_fingerprint=expected_fingerprint,
            ssh_passphrase=ssh_passphrase,
            prompt_for_key_passphrase=prompt_for_key_passphrase,
        )


def install_key(
    *,
    name: str,
    private_data: bytes,
    public_data: bytes,
    fingerprint: str,
    ssh_dir: pathlib.Path,
    force: bool,
) -> tuple[pathlib.Path, pathlib.Path]:
    name = validate_key_name(name)
    ssh_dir = ssh_dir.expanduser().resolve()
    private_path = ssh_dir / name
    public_path = ssh_dir / f"{name}.pub"
    if not force and (private_path.exists() or public_path.exists()):
        fail(
            f"目标密钥已存在：{private_path}。如需替换请明确指定 --force，"
            "避免误覆盖现有登录密钥。"
        )
    atomic_write(private_path, private_data, 0o600)
    atomic_write(public_path, public_data, 0o644)
    chmod_private(private_path)
    chmod_public(public_path)
    return private_path, public_path


def print_connection(args: argparse.Namespace, private_path: pathlib.Path, fingerprint: str) -> None:
    print(f"SSH 公钥指纹: {fingerprint}")
    print(f"私钥已写入: {private_path}")
    if getattr(args, "ssh_host", None) and getattr(args, "ssh_port", None):
        print(
            "连接命令: "
            f"ssh -o IdentitiesOnly=yes -i \"{private_path}\" "
            f"-p {args.ssh_port} root@{args.ssh_host}"
        )


def complete_install(args: argparse.Namespace, encrypted_path: pathlib.Path, expected_fp: Optional[str] = None) -> str:
    password = package_password(args)
    fp_header = expected_fp or getattr(args, "expected_fingerprint", None)
    if fp_header and not FINGERPRINT_RE.fullmatch(fp_header):
        fail("预期 SSH 指纹格式无效。")
    passphrase = key_passphrase(args)
    name, private_data, public_data, fingerprint = decrypt_and_validate(
        encrypted_path,
        password=password,
        key_name_hint=getattr(args, "key_name", None),
        expected_fingerprint=fp_header,
        ssh_passphrase=passphrase,
        prompt_for_key_passphrase=not getattr(args, "no_key_passphrase_prompt", False),
    )
    private_path, _ = install_key(
        name=name,
        private_data=private_data,
        public_data=public_data,
        fingerprint=fingerprint,
        ssh_dir=pathlib.Path(args.ssh_dir),
        force=args.force,
    )
    print_connection(args, private_path, fingerprint)
    return fingerprint


class ReceiverState:
    def __init__(self) -> None:
        self.done = threading.Event()
        # ``response_sent`` is deliberately separate from ``done``.  The
        # latter means that decrypt/install processing has finished; the
        # former means the HTTP status/body was handed to the socket.  A
        # temporary fpro client must remain alive until both have happened or
        # the sender can see an empty reply even after a successful install.
        self.response_sent = threading.Event()
        self.success = False
        self.error = ""
        self.fingerprint = ""
        self._claim_lock = threading.Lock()
        self._claimed = False

    def claim(self) -> bool:
        """Atomically reserve the one-shot POST for the first valid caller."""
        with self._claim_lock:
            if self._claimed:
                return False
            self._claimed = True
            return True

    def available(self) -> bool:
        with self._claim_lock:
            return not self._claimed and not self.done.is_set()


class OneShotHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, handler, *, token: str, args: argparse.Namespace, state: ReceiverState):
        super().__init__(address, handler)
        self.token = token
        self.args = args
        self.state = state
        self.endpoint = args.endpoint
        self.max_bytes = args.max_bytes
        self.work_dir = pathlib.Path(tempfile.mkdtemp(prefix="fpro-key-recv-"))
        self._shutdown_lock = threading.Lock()
        self._shutdown_timer: Optional[threading.Timer] = None
        self._shutdown_deadline = float("inf")

    def schedule_shutdown(self, delay: float = 0.0) -> None:
        """Schedule one shutdown, replacing it only when a deadline is sooner.

        The timeout timer is normally long-lived, while a completed one-shot
        request should stop the listener shortly after its response is sent.
        Keeping this operation idempotent avoids competing ``shutdown()``
        calls from the request worker, timeout timer and cleanup path.
        """
        delay = max(0.0, float(delay))
        deadline = time.monotonic() + delay
        with self._shutdown_lock:
            if deadline >= self._shutdown_deadline:
                return
            if self._shutdown_timer is not None:
                self._shutdown_timer.cancel()
            self._shutdown_deadline = deadline
            timer = threading.Timer(delay, self.shutdown)
            timer.daemon = True
            self._shutdown_timer = timer
            timer.start()

    def close(self) -> None:
        with self._shutdown_lock:
            if self._shutdown_timer is not None:
                self._shutdown_timer.cancel()
                self._shutdown_timer = None
        try:
            super().server_close()
        finally:
            shutil.rmtree(self.work_dir, ignore_errors=True)


class UploadHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        # Do not log URLs, headers, or remote addresses; tokens must not enter
        # terminal history or a shared service log.
        return

    @property
    def server_obj(self) -> OneShotHTTPServer:
        return self.server  # type: ignore[return-value]

    def send_json(self, payload: dict, code: int, *, mark_response: bool = False) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.close_connection = True
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            pass
        finally:
            if mark_response:
                self.server_obj.state.response_sent.set()

    def reject(self, code: int, message: str, *, finish: bool = False) -> None:
        self.send_json({"ok": False, "error": message}, code, mark_response=finish)
        if finish:
            self.server_obj.state.error = message
            self.server_obj.state.done.set()
            self.server_obj.schedule_shutdown(0.2)

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.reject(404, "not found")
            return
        supplied = self.headers.get("X-FPRO-Transfer-Token", "")
        if not hmac.compare_digest(supplied, self.server_obj.token):
            self.reject(401, "unauthorized")
            return
        self.send_json({"ok": True, "ready": self.server_obj.state.available()}, 200)

    def do_POST(self) -> None:
        server = self.server_obj
        if self.path != server.endpoint:
            self.reject(404, "not found")
            return
        supplied = self.headers.get("X-FPRO-Transfer-Token", "")
        if not hmac.compare_digest(supplied, server.token):
            self.reject(401, "unauthorized")
            return
        if server.state.done.is_set() or not server.state.claim():
            self.reject(409, "one-shot receiver already used")
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "-1")
        except ValueError:
            length = -1
        if length < 0:
            self.reject(411, "content-length required", finish=True)
            return
        if length > server.max_bytes:
            self.reject(413, "bundle too large", finish=True)
            return
        payload = self.rfile.read(length)
        if len(payload) != length:
            self.reject(400, "incomplete request", finish=True)
            return

        # The sender must provide the digest.  Accepting an omitted header
        # would turn the encrypted upload into a token-only transfer and
        # would no longer satisfy the one-shot delivery contract.
        supplied_digest = self.headers.get("X-FPRO-SHA256", "").strip()
        digest = hashlib.sha256(payload).hexdigest()
        if (
            not SHA256_RE.fullmatch(supplied_digest)
            or not hmac.compare_digest(supplied_digest.lower(), digest)
        ):
            self.reject(400, "sha256 mismatch", finish=True)
            return
        # The fingerprint is also mandatory.  It is checked again against the
        # public key inside the decrypted archive by ``complete_install``.
        expected_fp = self.headers.get("X-FPRO-Key-Fingerprint", "").strip()
        if not FINGERPRINT_RE.fullmatch(expected_fp):
            self.reject(400, "invalid fingerprint", finish=True)
            return

        encrypted = server.work_dir / "ssh-key.tar.gz.enc"
        try:
            encrypted.write_bytes(payload)
            chmod_private(encrypted)
            server.state.fingerprint = complete_install(server.args, encrypted, expected_fp)
            server.state.success = True
            self.send_json(
                {"ok": True, "sha256": digest, "fingerprint": server.state.fingerprint},
                200,
                mark_response=True,
            )
        except ReceiverError as exc:
            server.state.error = str(exc)
            self.send_json({"ok": False, "error": str(exc)}, 422, mark_response=True)
        except Exception as exc:  # defensive boundary for a one-shot process
            server.state.error = f"receiver error: {exc}"
            self.send_json(
                {"ok": False, "error": server.state.error}, 500, mark_response=True
            )
        finally:
            server.state.done.set()
            # Give the HTTP response a moment to flush before stopping the
            # listener; shutting down the socket immediately can make clients
            # observe a read timeout despite a successful install.
            server.schedule_shutdown(0.2)


def loopback_or_allowed(bind: str, allow_public: bool) -> None:
    normalized = bind.strip().lower()
    loopback = normalized in {"127.0.0.1", "localhost", "::1", "[::1]"}
    if not loopback and not allow_public:
        fail("接收器默认只允许绑定回环地址；如确需公网绑定，请明确指定 --allow-public。")


def make_receiver(args: argparse.Namespace, token: str) -> tuple[OneShotHTTPServer, ReceiverState]:
    loopback_or_allowed(args.bind, args.allow_public)
    if not 0 <= args.port <= 65535:
        fail("--port 必须在 0..65535 范围内（0 表示自动选择）。")
    if not args.endpoint.startswith("/") or "?" in args.endpoint or "#" in args.endpoint:
        fail("--endpoint 必须是以 / 开头且不含查询串的路径。")
    if args.max_bytes < 1 or args.max_bytes > MAX_BUNDLE_BYTES:
        fail(f"--max-bytes 必须在 1..{MAX_BUNDLE_BYTES} 范围内。")
    state = ReceiverState()
    try:
        server = OneShotHTTPServer(
            (args.bind, args.port),
            UploadHandler,
            token=token,
            args=args,
            state=state,
        )
    except OSError as exc:
        fail(f"无法监听接收器地址 {args.bind}:{args.port}：{exc}")
    return server, state


def run_listener(args: argparse.Namespace, *, wait_for_completion: bool = True) -> int:
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        fail("--timeout 必须是正数秒。")
    # Generate a token only when no token source was requested.  When the
    # caller supplies --token-file/--token-stdin/--token-env, honor that
    # source just like the proxy and fetch commands do.
    token_sources = (
        getattr(args, "token", None),
        getattr(args, "token_file", None),
        getattr(args, "token_stdin", False),
        getattr(args, "token_env", None),
    )
    token = (
        validate_token(read_secret(args, kind="token"))
        if any(token_sources)
        else secrets.token_urlsafe(32)
    )
    server, state = make_receiver(args, token)
    host, port = server.server_address[:2]
    print(f"本机接收器已监听: {host}:{port}{args.endpoint}")
    print(f"一次性 token（只显示本次）: {token}")
    print(f"FPRO_SSH_RECEIVER_URL=http://<fpro-server-host>:<remote-port>{args.endpoint}")
    print(f"FPRO_SSH_RECEIVER_TOKEN={token}")
    sys.stdout.flush()

    server.schedule_shutdown(args.timeout)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        state.done.wait(1.0)
        time.sleep(0.1)
        server.close()
    if wait_for_completion and not state.success:
        if state.error:
            print(f"接收失败: {state.error}", file=sys.stderr)
        else:
            print("接收超时或被取消。", file=sys.stderr)
        return 1
    return 0


def fetch_remote(args: argparse.Namespace) -> int:
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        fail("--timeout 必须是正数秒。")
    token = validate_token(read_secret(args, kind="token"))
    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        fail("--url 只允许使用 http:// 或 https:// URL。")
    request = urllib.request.Request(
        args.url,
        method="GET",
        headers={
            "X-FPRO-Transfer-Token": token,
            "Accept": "application/octet-stream",
            "Connection": "close",
        },
    )
    temporary: Optional[pathlib.Path] = None
    try:
        try:
            response = urllib.request.urlopen(request, timeout=args.timeout)
        except urllib.error.HTTPError as exc:
            detail = decode_text(exc.read(512), limit=512)
            fail(f"远端接收端点返回 HTTP {exc.code}: {detail}")
        with response:
            raw_length = response.headers.get("Content-Length")
            if raw_length:
                try:
                    announced = int(raw_length)
                except ValueError:
                    fail("远端返回了无效的 Content-Length。")
                if announced > args.max_bytes:
                    fail("远端密钥包超过大小限制。")
            fd, path = tempfile.mkstemp(prefix="fpro-key-", suffix=".enc")
            os.close(fd)
            temporary = pathlib.Path(path)
            digest = hashlib.sha256()
            total = 0
            with temporary.open("wb") as output:
                while True:
                    block = response.read(64 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > args.max_bytes:
                        fail("远端密钥包超过大小限制。")
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            announced_digest = response.headers.get("X-FPRO-SHA256", "").strip()
            actual_digest = digest.hexdigest()
            if (
                not SHA256_RE.fullmatch(announced_digest)
                or not hmac.compare_digest(announced_digest.lower(), actual_digest)
            ):
                fail("收到的密钥包 SHA-256 校验失败。")
            expected_fp = response.headers.get("X-FPRO-Key-Fingerprint", "").strip()
            if not FINGERPRINT_RE.fullmatch(expected_fp):
                fail("远端返回的 SSH 指纹格式无效。")
            print(f"已接收加密密钥包 ({total} bytes, sha256={actual_digest})")
            fingerprint = complete_install(args, temporary, expected_fp)
            print(f"接收并解密完成，指纹: {fingerprint}")
            return 0
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def decrypt_local(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.input).expanduser().resolve()
    if not path.is_file():
        fail(f"找不到加密密钥包：{path}")
    fingerprint = complete_install(args, path)
    print(f"解密并安装完成，指纹: {fingerprint}")
    return 0


def url_host(host: str) -> str:
    """Format an IPv4/hostname/IPv6 address for an HTTP URL."""
    if host.startswith("[") and host.endswith("]"):
        return host
    if ":" in host:
        return f"[{host}]"
    return host


def wait_for_health(host: str, port: int, token: str, timeout: float) -> bool:
    """Wait for the actual authenticated receiver, not a bare TCP socket.

    A bare ``connect()`` creates a work connection in fpro and then closes it
    without sending an HTTP request.  Depending on timing, that half-open
    connection can delay the first real upload.  A token-authenticated health
    request exercises the complete path and is cleanly closed by the receiver.
    """
    if timeout <= 0:
        return False
    url = f"http://{url_host(host)}:{port}/healthz"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = max(0.1, deadline - time.monotonic())
        try:
            request = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "X-FPRO-Transfer-Token": token,
                    "Connection": "close",
                },
            )
            with urllib.request.urlopen(request, timeout=min(3.0, remaining)) as response:
                body = response.read(1024)
                if response.status != 200:
                    raise OSError(f"health HTTP {response.status}")
                try:
                    payload = json.loads(decode_text(body))
                except (TypeError, ValueError):
                    payload = {}
                if payload.get("ok") is True and payload.get("ready") is True:
                    return True
        except (OSError, urllib.error.URLError, urllib.error.HTTPError):
            time.sleep(0.25)
    return False


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        try:
            process.kill()
            process.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            pass


def start_fpro_proxy(args: argparse.Namespace) -> int:
    binary = pathlib.Path(args.fpro_binary).expanduser().resolve()
    if not binary.is_file():
        fail(f"找不到 fpro-client 二进制：{binary}")
    if not 1 <= args.remote_port <= 65535:
        fail("--remote-port 必须在 1..65535 范围内。")
    if not 1 <= args.server_port <= 65535:
        fail("--server-port 必须在 1..65535 范围内。")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        fail("--timeout 必须是正数秒。")
    if not math.isfinite(args.proxy_timeout) or args.proxy_timeout <= 0:
        fail("--proxy-timeout 必须是正数秒。")
    if not math.isfinite(args.response_grace) or args.response_grace < 0:
        fail("--response-grace 必须是非负数秒。")
    receiver_token = validate_token(read_secret(args, kind="token"))
    fpro_token = validate_fpro_token(read_secret(args, kind="fpro_token"))
    for path_arg in (args.tls_cert, args.tls_key, args.tls_ca):
        if not pathlib.Path(path_arg).expanduser().is_file():
            fail(f"TLS 文件不存在：{path_arg}")

    server, state = make_receiver(args, receiver_token)
    local_host, local_port = server.server_address[:2]
    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix="fpro-key-proxy-"))
    receiver_token_file = temp_dir / "receiver-token"
    receiver_token_file.write_text(receiver_token + "\n", encoding="utf-8")
    chmod_private(receiver_token_file)
    fpro_token_file = temp_dir / "fpro-auth-token"
    fpro_token_file.write_text(fpro_token + "\n", encoding="utf-8")
    chmod_private(fpro_token_file)
    log_file = temp_dir / "fpro-client.log"
    client_id = args.client_id or f"fpro-key-delivery-{secrets.token_hex(6)}"
    proxy_name = args.proxy_name or f"fpro-key-delivery-{secrets.token_hex(4)}"
    user = args.fpro_user or "fpro-key-delivery"
    config = temp_dir / "fpro-client.toml"
    config.write_text(
        "\n".join(
            [
                f"serverAddr = {toml_quote(args.server_addr)}",
                f"serverPort = {args.server_port}",
                "loginFailExit = true",
                f"user = {toml_quote(user)}",
                f"clientID = {toml_quote(client_id)}",
                f"log.to = {toml_quote(str(log_file))}",
                "log.level = \"warn\"",
                "auth.method = \"aes\"",
                "auth.tokenSource.type = \"file\"",
                f"auth.tokenSource.file.path = {toml_quote(str(fpro_token_file))}",
                "auth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]",
                "transport.protocol = \"tcp\"",
                "transport.tls.enable = true",
                f"transport.tls.certFile = {toml_quote(str(pathlib.Path(args.tls_cert).expanduser()))}",
                f"transport.tls.keyFile = {toml_quote(str(pathlib.Path(args.tls_key).expanduser()))}",
                f"transport.tls.trustedCaFile = {toml_quote(str(pathlib.Path(args.tls_ca).expanduser()))}",
                f"transport.tls.serverName = {toml_quote(args.tls_server_name or args.server_addr)}",
                "transport.tls.disableCustomTLSFirstByte = true",
                "",
                "[[proxies]]",
                f"name = {toml_quote(proxy_name)}",
                "type = \"tcp\"",
                "localIP = \"127.0.0.1\"",
                f"localPort = {local_port}",
                f"remotePort = {args.remote_port}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    chmod_private(config)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log_handle = log_file.open("ab")
    process: Optional[subprocess.Popen] = None
    try:
        server.schedule_shutdown(args.timeout)
        process = subprocess.Popen(
            [str(binary), "-c", str(config)],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        if not wait_for_health(
            args.server_addr, args.remote_port, receiver_token, args.proxy_timeout
        ):
            detail = read_text_tail(log_file)
            fail(f"临时 fpro 端口未上线。客户端日志：{detail}")
        remote_url_host = url_host(args.server_addr)
        # Emit an ASCII-only event before the localized status line.  The
        # packaged GUI uses this marker so readiness detection remains correct
        # even when a Windows code page is misconfigured.
        print(READY_MARKER)
        print(f"临时 fpro 通道已建立: {remote_url_host}:{args.remote_port}")
        print(f"请将以下变量传给容器内 install.sh（token 不要写入 Git）：")
        print(f"FPRO_SSH_RECEIVER_URL=http://{remote_url_host}:{args.remote_port}{args.endpoint}")
        print(f"FPRO_SSH_RECEIVER_TOKEN={receiver_token}")
        print("等待一次性密钥包传输……")
        sys.stdout.flush()
        while not state.done.wait(0.25):
            if process.poll() is not None:
                detail = read_text_tail(log_file)
                fail(f"临时 fpro 客户端提前退出。日志：{detail}")
        # Keep the fpro process alive until the response was flushed, then use
        # a short configurable grace period for the bytes to cross frps/frpc.
        # A fixed 30-second sleep made every successful delivery needlessly
        # slow; the default is deliberately just a few round trips.
        response_wait = max(1.0, min(10.0, args.response_grace + 1.0))
        if not state.response_sent.wait(response_wait):
            fail("HTTP 响应未能写入本机接收器。")
        time.sleep(args.response_grace)
        if not state.success:
            fail(state.error or "接收失败或超时。")
        print("一次性密钥包已在本机解密并安装；临时 fpro 通道将关闭。")
        return 0
    finally:
        server.schedule_shutdown(0.0)
        state.done.wait(1.0)
        time.sleep(0.1)
        server_thread.join(timeout=2.0)
        server.close()
        if process is not None:
            terminate_process(process)
        try:
            log_handle.close()
        except Exception:
            pass
        shutil.rmtree(temp_dir, ignore_errors=True)


def add_secret_options(
    parser: argparse.ArgumentParser,
    *,
    token: bool = False,
    kind: Optional[str] = None,
) -> None:
    secret_kind = kind or ("token" if token else "password")
    option_kind = secret_kind.replace("_", "-")
    parser.add_argument(
        f"--{option_kind}-file",
        dest=f"{secret_kind}_file",
        help=f"从文件读取 {secret_kind}（文件不会上传）",
    )
    parser.add_argument(
        f"--{option_kind}-stdin",
        dest=f"{secret_kind}_stdin",
        action="store_true",
        help=f"从 stdin 读取 {secret_kind}",
    )
    parser.add_argument(
        f"--{option_kind}-env",
        dest=f"{secret_kind}_env",
        help=f"从指定环境变量读取 {secret_kind}",
    )
    if token or secret_kind == "fpro_token":
        parser.add_argument(
            f"--{option_kind}",
            dest=secret_kind,
            help=f"方便测试；生产环境建议使用 --{option_kind}-file/--{option_kind}-env",
        )


def add_key_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ssh-dir", default=str(pathlib.Path.home() / ".ssh"))
    parser.add_argument("--key-name", help="预期的 SSH 私钥文件名")
    parser.add_argument("--expected-fingerprint")
    parser.add_argument("--force", action="store_true", help="允许替换同名本地密钥")
    parser.add_argument("--key-passphrase-file")
    parser.add_argument("--key-passphrase-stdin", action="store_true")
    parser.add_argument("--no-key-passphrase-prompt", action="store_true")
    parser.add_argument("--ssh-host")
    parser.add_argument("--ssh-port", type=int)
    parser.add_argument("--max-bytes", type=int, default=MAX_BUNDLE_BYTES)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    decrypt = sub.add_parser("decrypt", help="在本机解密并安装已有 .enc 密钥包")
    decrypt.add_argument("--input", required=True)
    add_secret_options(decrypt)
    add_key_options(decrypt)

    fetch = sub.add_parser("fetch", help="从临时 fpro/HTTP 端点拉取并安装密钥包")
    fetch.add_argument("--url", required=True)
    add_secret_options(fetch, token=True)
    add_secret_options(fetch, token=False)
    fetch.add_argument("--timeout", type=float, default=60)
    add_key_options(fetch)

    listen = sub.add_parser("listen", help="监听一次 HTTP POST 并安装密钥包")
    listen.add_argument("--bind", default="127.0.0.1")
    listen.add_argument("--port", type=int, default=0)
    listen.add_argument("--endpoint", default="/v1/ssh-key")
    listen.add_argument("--allow-public", action="store_true")
    listen.add_argument("--timeout", type=float, default=300)
    listen.add_argument("--remote-port", type=int, default=0, help="仅用于提示输出")
    add_secret_options(listen, token=True)
    add_secret_options(listen, token=False)
    add_key_options(listen)

    proxy = sub.add_parser("proxy", help="启动本机接收器并建立临时 fpro TCP 代理")
    proxy.add_argument("--fpro-binary", required=True)
    proxy.add_argument("--server-addr", required=True)
    proxy.add_argument("--server-port", type=int, default=7000)
    proxy.add_argument("--remote-port", type=int, required=True)
    proxy.add_argument("--tls-cert", required=True)
    proxy.add_argument("--tls-key", required=True)
    proxy.add_argument("--tls-ca", required=True)
    proxy.add_argument("--tls-server-name")
    proxy.add_argument("--fpro-user")
    proxy.add_argument("--client-id")
    proxy.add_argument("--proxy-name")
    proxy.add_argument("--bind", default="127.0.0.1")
    proxy.add_argument("--port", type=int, default=0)
    proxy.add_argument("--endpoint", default="/v1/ssh-key")
    proxy.add_argument("--allow-public", action="store_true")
    proxy.add_argument("--proxy-timeout", type=float, default=45)
    proxy.add_argument(
        "--response-grace",
        type=float,
        default=3.0,
        help="HTTP 响应写入后保留临时 fpro 通道的秒数（默认 3）",
    )
    proxy.add_argument("--timeout", type=float, default=300)
    add_secret_options(proxy, token=True)
    add_secret_options(proxy, kind="fpro_token")
    add_secret_options(proxy, token=False)
    add_key_options(proxy)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    # The GUI launches this module with stdout/stderr connected to a pipe.
    # Force UTF-8 for that worker stream so Chinese diagnostics are not
    # encoded with the host's legacy CP936 code page.  Interactive terminals
    # retain their native encoding in ``configure_stdio``.
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "decrypt":
            return decrypt_local(args)
        if args.command == "fetch":
            return fetch_remote(args)
        if args.command == "listen":
            return run_listener(args)
        if args.command == "proxy":
            return start_fpro_proxy(args)
        parser.error("未知命令")
    except ReceiverError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
