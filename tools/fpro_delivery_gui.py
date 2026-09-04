#!/usr/bin/env python3
"""Windows front end for one-shot Cloud Studio SSH key delivery.

The GUI deliberately keeps secrets out of command lines and configuration
files.  It downloads the encrypted repository artifacts, decrypts only the
short-lived local staging copy, starts the one-shot receiver/proxy, and copies
the bootstrap command for the operator to run in the Cloud Studio terminal.
The browser/terminal is never controlled automatically.  The receiver worker
remains in ``fpro_ssh_receiver.py`` so the CLI and the packaged app use the
same checks.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import platform
import queue
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover - only relevant on non-GUI Python builds
    tk = None
    filedialog = messagebox = ttk = None

try:
    from fpro_crypto import CryptoError, decrypt_file
except ImportError:  # pragma: no cover - package-relative import
    from .fpro_crypto import CryptoError, decrypt_file


try:
    import fpro_ssh_receiver  # noqa: F401 - kept as a PyInstaller dependency
except ImportError:  # pragma: no cover - package-relative import
    from . import fpro_ssh_receiver  # noqa: F401


APP_NAME = "FPRO Cloud Studio 临时通道"
DEFAULT_RAW_BASE = "https://raw.githubusercontent.com/bot0577/fpro-cloudstudio-deploy/main"
CONFIG_ARTIFACT = "fpro-deploy.tar.gz.enc"
MAX_CONFIG_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024
KEY_NAME_DEFAULT = "fpro-cloudstudio"
KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
DEFAULT_TEMP_PORT_MIN = 7001
DEFAULT_TEMP_PORT_MAX = 7499
# Keep this in sync with ``fpro_ssh_receiver.READY_MARKER``.  It is ASCII by
# design, so readiness detection works even if a legacy Windows code page is
# involved in the child process stream.
WORKER_READY_MARKER = "__FPRO_EVENT_READY__"


class AppError(RuntimeError):
    """An actionable error suitable for display in the GUI."""


def app_dir() -> pathlib.Path:
    if getattr(sys, "frozen", False):
        return pathlib.Path(sys.executable).resolve().parent
    return pathlib.Path(__file__).resolve().parent.parent


def settings_path() -> pathlib.Path:
    root = pathlib.Path(os.environ.get("APPDATA", pathlib.Path.home()))
    return root / "fpro-delivery" / "settings.json"


def guess_repo() -> pathlib.Path:
    candidates = [
        app_dir(),
        app_dir().parent,
        pathlib.Path.cwd(),
        pathlib.Path(__file__).resolve().parent.parent,
    ]
    for candidate in candidates:
        try:
            if (candidate / CONFIG_ARTIFACT).is_file():
                return candidate
        except OSError:
            pass
    return pathlib.Path()


def windows_binary_name() -> str:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"} or "arm64" in machine:
        return "fpro-client_windows_arm64.exe"
    if machine in {"amd64", "x86_64", "x64"} or "64" in machine:
        return "fpro-client_windows_amd64.exe"
    raise AppError(f"暂不支持当前 Windows 架构：{platform.machine()}")


def select_temp_port(requested: Optional[int], ssh_port: Optional[int]) -> int:
    """Choose a likely-allowed one-shot port when the user leaves it blank.

    Cloud Studio's normal SSH mapping occupies one port, so the temporary
    receiver must use a different port.  The encrypted client configuration
    conventionally keeps user ports in 7001-7499; prefer the port immediately
    after the SSH mapping and fall back to the first port in that range.
    The user can still override this in Advanced settings for a custom server.
    """
    if requested is not None:
        if not 1 <= requested <= 65535:
            raise AppError("临时远端端口必须在 1-65535 范围内。")
        if ssh_port is not None and requested == ssh_port:
            raise AppError("临时接收端口不能与 SSH 映射端口相同。")
        return requested
    candidates: list[int] = []
    if ssh_port is not None and DEFAULT_TEMP_PORT_MIN <= ssh_port < DEFAULT_TEMP_PORT_MAX:
        candidates.append(ssh_port + 1)
    candidates.extend(
        port
        for port in range(DEFAULT_TEMP_PORT_MIN, DEFAULT_TEMP_PORT_MAX + 1)
        if port not in candidates and port != ssh_port
    )
    if not candidates:
        raise AppError("无法自动选择临时远端端口，请在高级设置中手动填写。")
    return candidates[0]


def shell_quote(value: str) -> str:
    """Quote one value for POSIX shell commands typed into Cloud Studio."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def decode_worker_line(value: bytes | str) -> str:
    """Decode one worker output line without Windows CP936 mojibake."""
    if isinstance(value, str):
        return value.rstrip("\r\n")
    raw = value.rstrip(b"\r\n")
    if not raw:
        return ""
    for encoding in ("utf-8", "gb18030"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\ufffd" not in text:
            return text
    return raw.decode("utf-8", "replace")


def url_host(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host
    if ":" in host:
        return f"[{host}]"
    return host


def normalize_raw_base(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise AppError("Raw 地址必须是 HTTPS URL。")
    return value


def write_private(path: pathlib.Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def validate_windows_binary(path: pathlib.Path) -> pathlib.Path:
    """Check that a selected/decrypted artifact looks like a Windows PE."""
    try:
        with path.open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise AppError(f"文件不是有效的 Windows fpro-client：{path.name}")
    except OSError as exc:
        raise AppError(f"无法读取 Windows fpro-client：{exc}") from exc
    return path


def download_file(url: str, destination: pathlib.Path, *, log: Callable[[str], None]) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise AppError(f"只允许通过 HTTPS 下载：{url}")
    log(f"下载 {pathlib.PurePosixPath(parsed.path).name} …")
    request = urllib.request.Request(url, headers={"User-Agent": "FPRO-Delivery/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            final_url = urllib.parse.urlparse(response.geturl())
            if final_url.scheme != "https" or not final_url.netloc:
                raise AppError("下载被重定向到非 HTTPS 地址，已拒绝。")
            announced = response.headers.get("Content-Length")
            if announced and int(announced) > MAX_CONFIG_BYTES:
                raise AppError("远程文件超过大小限制。")
            temporary = destination.with_suffix(destination.suffix + ".part")
            total = 0
            with temporary.open("wb") as stream:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_CONFIG_BYTES:
                        raise AppError("远程文件超过大小限制。")
                    stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
    except urllib.error.HTTPError as exc:
        raise AppError(f"下载失败（HTTP {exc.code}）：{url}") from exc
    except urllib.error.URLError as exc:
        raise AppError(f"下载失败：{exc.reason}") from exc
    except (OSError, ValueError) as exc:
        raise AppError(f"下载失败：{exc}") from exc


def safe_member_name(name: str) -> str:
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) > 8:
        raise AppError("加密配置包含不安全的归档路径。")
    return "/".join(path.parts)


PAYLOAD_FILES = (
    "certs/ca.crt",
    "certs/client.crt",
    "certs/client.key",
    "certs/auth-token",
    "fpro-client.toml",
)


def extract_payload(archive_bytes: bytes, destination: pathlib.Path) -> pathlib.Path:
    """Extract only the mTLS/config files needed by the local proxy."""
    try:
        archive = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise AppError(f"配置包不是有效的 tar.gz：{exc}") from exc

    members: dict[str, tarfile.TarInfo] = {}
    with archive:
        for member in archive.getmembers():
            name = safe_member_name(member.name)
            if not name or not member.isfile():
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise AppError(f"配置包成员过大：{name}")
            members[name] = member
        destination.mkdir(parents=True, exist_ok=True)
        for relative in PAYLOAD_FILES:
            member = None
            for candidate in (relative, f"payload/{relative}"):
                if candidate in members:
                    member = members[candidate]
                    break
            if member is None:
                raise AppError(f"配置包缺少必需文件：{relative}")
            stream = archive.extractfile(member)
            if stream is None:
                raise AppError(f"无法读取配置包成员：{relative}")
            data = stream.read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES:
                raise AppError(f"配置包成员过大：{relative}")
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            write_private(output, data)
    return destination


def toml_value(text: str, key: str) -> str:
    pattern = re.compile(
        rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*(?:#.*)?$",
        re.MULTILINE,
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        return value
    return ""


def config_values(config_path: pathlib.Path) -> dict[str, str]:
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AppError(f"读取 fpro-client.toml 失败：{exc}") from exc
    values = {
        "server_addr": toml_value(text, "serverAddr"),
        "server_port": toml_value(text, "serverPort"),
        "tls_server_name": toml_value(text, "transport.tls.serverName"),
        "user": toml_value(text, "user"),
        "remote_port": "",
    }
    # Prefer the SSH proxy's remote port; fall back to the first proxy port.
    blocks = re.split(r"^\s*\[\[proxies\]\]\s*$", text, flags=re.MULTILINE)
    fallback = ""
    for block in blocks[1:]:
        port = toml_value(block, "remotePort")
        if port and not fallback:
            fallback = port
        if "cloudstudio-ssh" in block or "ssh" in toml_value(block, "name"):
            values["remote_port"] = port
            break
    values["remote_port"] = values["remote_port"] or fallback
    return values


def make_remote_command(
    raw_base: str,
    receiver_url: str,
    key_name: str = KEY_NAME_DEFAULT,
) -> str:
    """Build a one-paste bootstrap command with two hidden prompts.

    The first prompt captures the package password into a temporary file; the
    second captures the one-shot receiver token.  Neither secret appears in
    shell history or the command text.  The command is copied to the
    clipboard and run manually in the Cloud Studio terminal.
    """
    if not KEY_NAME_RE.fullmatch(key_name):
        raise AppError("SSH 密钥名只能包含字母、数字、点、下划线和连字符。")
    install_url = normalize_raw_base(raw_base) + "/install.sh"
    fetch_script = (
        f"if command -v curl >/dev/null 2>&1; then curl -fsSL {shell_quote(install_url)}; "
        f"elif command -v wget >/dev/null 2>&1; then wget -qO- {shell_quote(install_url)}; "
        "else echo 'curl or wget is required' >&2; exit 127; fi"
    )
    return (
        "set -o pipefail; umask 077; "
        "FPRO_PW_FILE=\"$(mktemp)\" || exit 1; "
        "FPRO_TOKEN_FILE=\"$(mktemp)\" || { rm -f -- \"$FPRO_PW_FILE\"; exit 1; }; "
        "trap 'rm -f -- \"$FPRO_PW_FILE\" \"$FPRO_TOKEN_FILE\"' EXIT HUP INT TERM; "
        # Keep prompts ASCII: Cloud Studio terminals may use a different
        # locale, and an ASCII command is never rendered as mojibake there.
        "printf '\\nFPRO package password: '; read -r -s FPRO_PACKAGE_PASSWORD; "
        "printf '%s' \"$FPRO_PACKAGE_PASSWORD\" >\"$FPRO_PW_FILE\"; "
        "unset FPRO_PACKAGE_PASSWORD; "
        "printf '\\nFPRO one-time transfer token: '; read -r -s FPRO_TRANSFER_TOKEN; "
        "printf '%s\\n' \"$FPRO_TRANSFER_TOKEN\" >\"$FPRO_TOKEN_FILE\"; "
        "unset FPRO_TRANSFER_TOKEN; "
        f"{fetch_script} | sudo env "
        "FPRO_PACKAGE_PASSWORD_FILE=\"$FPRO_PW_FILE\" "
        "FPRO_SSH_GENERATE=1 "
        f"FPRO_SSH_KEY_NAME={shell_quote(key_name)} "
        f"FPRO_SSH_RECEIVER_URL={shell_quote(receiver_url)} "
        "FPRO_SSH_RECEIVER_TOKEN_FILE=\"$FPRO_TOKEN_FILE\" "
        "FPRO_SSH_RECEIVER_TIMEOUT=90 bash; "
        "rc=$?; exit $rc"
    )


@dataclass
class PreparedAssets:
    temp_root: pathlib.Path
    binary: pathlib.Path
    client_crt: pathlib.Path
    client_key: pathlib.Path
    ca_crt: pathlib.Path
    fpro_token: pathlib.Path
    package_password: pathlib.Path
    receiver_token: pathlib.Path
    receiver_token_value: str
    server_addr: str
    server_port: int
    tls_server_name: str
    fpro_user: str
    key_name: str
    ssh_port: Optional[int]
    remote_port: int
    raw_base: str


@dataclass(frozen=True)
class RunOptions:
    raw_base: str
    temp_port: Optional[int]
    repo: str
    binary: str
    server_addr: str
    server_port: str
    tls_server_name: str
    ssh_dir: str
    key_name: str


def worker_command(args: list[str]) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--receiver-worker", *args]
    return [sys.executable, str(pathlib.Path(__file__).resolve()), "--receiver-worker", *args]


class DeliveryApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("900x760")
        self.minsize(760, 640)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.worker: Optional[subprocess.Popen[bytes]] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.proxy_ready = False
        self.current_token = ""
        self.current_url = ""
        self.current_command = ""
        self.command_placeholder = (
            "启动临时通道后，这里会自动生成一条可直接粘贴到 Cloud Studio 的 bash 命令。"
        )
        self.prepared: Optional[PreparedAssets] = None
        self.temp_root: Optional[pathlib.Path] = None
        self.load_settings()
        self.build_ui()
        self.after(100, self.process_events)

    def load_settings(self) -> None:
        values: dict[str, object] = {}
        try:
            values = json.loads(settings_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        repo_guess = guess_repo()
        self.raw_var = tk.StringVar(value=str(values.get("raw_base", DEFAULT_RAW_BASE)))
        self.repo_var = tk.StringVar(value=str(values.get("repo", repo_guess)))
        self.binary_var = tk.StringVar(value=str(values.get("binary", "")))
        self.server_var = tk.StringVar(value=str(values.get("server_addr", "")))
        self.server_port_var = tk.StringVar(value=str(values.get("server_port", "")))
        self.temp_port_var = tk.StringVar(value=str(values.get("temp_port", "")))
        self.tls_name_var = tk.StringVar(value=str(values.get("tls_server_name", "")))
        self.ssh_dir_var = tk.StringVar(value=str(values.get("ssh_dir", pathlib.Path.home() / ".ssh")))
        self.key_name_var = tk.StringVar(value=str(values.get("key_name", KEY_NAME_DEFAULT)))

    def build_ui(self) -> None:
        outer = ttk.Frame(self, padding=14)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="fpro Cloud Studio 临时通道与 SSH 密钥交付", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text="输入密钥传输密码后点击开始；程序会自动生成并复制 Cloud Studio 的 bash 命令。",
            foreground="#555555",
        ).pack(anchor="w", pady=(2, 12))

        form = ttk.LabelFrame(outer, text="部署参数", padding=10)
        form.pack(fill="x")
        self.add_row(form, 0, "密钥传输密码（唯一必填）", "password", None)
        ttk.Label(
            form,
            text="该密码同时用于解密配置和接收的 SSH 私钥包；不会保存到设置文件。",
            foreground="#777777",
        ).grid(row=1, column=1, sticky="w", pady=(2, 0))

        self.advanced_toggle = ttk.Button(
            outer,
            text="显示高级设置（通常不用改）",
            command=self.toggle_advanced,
        )
        self.advanced_toggle.pack(anchor="w", pady=(10, 0))
        advanced = ttk.LabelFrame(outer, text="高级设置", padding=10)
        self.advanced_frame = advanced
        self.add_row(
            advanced,
            0,
            "临时远端端口（可留空）",
            "entry",
            self.temp_port_var,
            hint="留空自动选择；仅在自定义服务端时填写",
        )
        self.add_row(advanced, 1, "本地仓库目录", "browse", self.repo_var, self.browse_repo)
        self.add_row(advanced, 2, "本机 fpro-client.exe", "browse", self.binary_var, self.browse_binary)
        self.add_row(advanced, 3, "服务端地址覆盖", "entry", self.server_var, hint="留空则从加密配置读取")
        self.add_row(advanced, 4, "控制端口覆盖", "entry", self.server_port_var, hint="留空则从加密配置读取")
        self.add_row(advanced, 5, "TLS Server Name 覆盖", "entry", self.tls_name_var, hint="留空则从加密配置读取")
        self.add_row(advanced, 6, "SSH 私钥目录", "entry", self.ssh_dir_var)
        self.add_row(advanced, 7, "SSH 密钥名", "entry", self.key_name_var)
        self.add_row(advanced, 8, "Raw 基础地址", "entry", self.raw_var)

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(12, 8))
        self.start_button = ttk.Button(buttons, text="启动临时通道", command=self.start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="停止", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))

        # The browser/terminal is intentionally not automated.  Keep the
        # command panel visible from launch so the operator always has one
        # obvious place to copy the command; its text is filled as soon as the
        # one-shot tunnel receives a usable endpoint.
        self.command_frame = ttk.LabelFrame(
            outer, text="Cloud Studio bash 命令", padding=8
        )
        self.command_frame.pack(fill="x", pady=(6, 0))
        ttk.Label(
            self.command_frame,
            text="通道建立后命令会自动复制到剪贴板；也可以在这里再次复制，然后粘贴到 Cloud Studio 终端并回车。",
            foreground="#777777",
        ).pack(anchor="w")
        command_text_frame = ttk.Frame(self.command_frame)
        command_text_frame.pack(fill="x", pady=(6, 0))
        self.command_text = tk.Text(
            command_text_frame,
            height=7,
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
            relief="sunken",
            borderwidth=1,
        )
        command_scrollbar = ttk.Scrollbar(
            command_text_frame, orient="vertical", command=self.command_text.yview
        )
        self.command_text.configure(yscrollcommand=command_scrollbar.set)
        self.command_text.configure(takefocus=1)
        self.command_text.bind("<Control-c>", self.copy_command_event)
        self.command_text.bind("<Control-a>", self.select_command_event)
        self.command_text.pack(side="left", fill="x", expand=True)
        command_scrollbar.pack(side="right", fill="y")
        self.set_command_preview(self.command_placeholder)
        command_buttons = ttk.Frame(self.command_frame)
        command_buttons.pack(fill="x", pady=(6, 0))
        self.copy_button = ttk.Button(
            command_buttons,
            text="复制 bash 命令",
            command=self.copy_command,
            state="disabled",
        )
        self.copy_button.pack(side="left")
        self.copy_token_button = ttk.Button(
            command_buttons,
            text="复制一次性 token",
            command=self.copy_token,
            state="disabled",
        )
        self.copy_token_button.pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="就绪")
        self.status_label = ttk.Label(outer, textvariable=self.status_var, foreground="#1f5f9e")
        self.status_label.pack(anchor="w")
        log_frame = ttk.LabelFrame(outer, text="运行日志", padding=6)
        log_frame.pack(fill="both", expand=True, pady=(6, 0))
        # Microsoft YaHei has complete CJK glyph coverage on normal Windows
        # installations; Consolas alone can make otherwise-correct Chinese
        # diagnostics look like boxes or broken text.
        self.log_text = tk.Text(
            log_frame,
            height=14,
            wrap="word",
            state="disabled",
            font=("Microsoft YaHei UI", 9),
        )
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.password_entry.focus_set()
        self.password_entry.bind("<Return>", lambda _event: self.start())

    def set_command_preview(self, command: str) -> None:
        """Update the visible, read-only command area without touching the clipboard."""
        if not hasattr(self, "command_text"):
            return
        self.command_text.configure(state="normal")
        self.command_text.delete("1.0", "end")
        self.command_text.insert("1.0", command)
        self.command_text.configure(state="disabled")

    def copy_command_event(self, _event=None):
        """Allow Ctrl+C directly from the read-only command preview."""
        self.copy_command()
        return "break"

    def select_command_event(self, _event=None):
        """Allow Ctrl+A directly from the read-only command preview."""
        self.command_text.tag_add("sel", "1.0", "end-1c")
        return "break"

    def show_command_controls(self) -> None:
        """Enable command actions once the temporary tunnel is ready."""
        if not self.current_url:
            return
        self.copy_button.configure(state="normal" if self.current_command else "disabled")
        self.copy_token_button.configure(state="normal" if self.current_token else "disabled")

    def hide_command_controls(self) -> None:
        self.copy_button.configure(state="disabled")
        self.copy_token_button.configure(state="disabled")
        self.set_command_preview(self.command_placeholder)

    def toggle_advanced(self) -> None:
        if self.advanced_frame.winfo_manager():
            self.advanced_frame.pack_forget()
            self.advanced_toggle.configure(text="显示高级设置（通常不用改）")
        else:
            self.advanced_frame.pack(fill="x", pady=(6, 0))
            self.advanced_toggle.configure(text="隐藏高级设置")

    def add_row(self, parent, row: int, label: str, kind: str, variable, extra=None, hint: str = "") -> None:
        ttk.Label(parent, text=label, width=24).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=3)
        if kind == "password":
            widget = ttk.Entry(parent, width=70, show="•")
            self.password_entry = widget
        elif kind == "entry":
            widget = ttk.Entry(parent, textvariable=variable, width=70)
        elif kind == "check":
            widget = ttk.Checkbutton(parent, variable=variable)
        elif kind == "browse":
            widget = ttk.Entry(parent, textvariable=variable, width=58)
            button = ttk.Button(parent, text="选择…", command=extra, width=8)
            widget.grid(row=row, column=1, sticky="ew", pady=3)
            button.grid(row=row, column=2, sticky="e", padx=(6, 0), pady=3)
            if hint:
                ttk.Label(parent, text=hint, foreground="#777777").grid(row=row, column=3, sticky="w", padx=(8, 0))
            parent.columnconfigure(1, weight=1)
            return
        else:
            widget = ttk.Label(parent, text="")
        widget.grid(row=row, column=1, sticky="w", pady=3)
        if hint:
            ttk.Label(parent, text=hint, foreground="#777777").grid(row=row, column=2, sticky="w", padx=(8, 0))
        parent.columnconfigure(1, weight=1)

    def browse_repo(self) -> None:
        path = filedialog.askdirectory(title="选择 fpro-deploy 仓库目录")
        if path:
            self.repo_var.set(path)

    def browse_binary(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 Windows fpro-client",
            filetypes=[("fpro-client", "*.exe"), ("加密文件", "*.enc"), ("所有文件", "*.*")],
        )
        if path:
            self.binary_var.set(path)

    def log(self, message: str) -> None:
        if self.current_token:
            message = message.replace(self.current_token, "<一次性 token 已隐藏>")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def post(self, event: str, value: object = None) -> None:
        self.events.put((event, value))

    def process_events(self) -> None:
        try:
            while True:
                event, value = self.events.get_nowait()
                if event == "log":
                    self.log(str(value))
                elif event == "status":
                    self.status_var.set(str(value))
                elif event == "ready":
                    self.on_proxy_ready()
                elif event == "command_preview":
                    # The endpoint is known while the worker is coming up;
                    # show the command early so it never has to be retyped.
                    if self.prepared is not None:
                        self.set_command_preview(str(value))
                elif event == "done":
                    self.on_worker_done(int(value))
                elif event == "error":
                    self.on_error(str(value))
                elif event == "set":
                    name, text = value  # type: ignore[misc]
                    getattr(self, f"{name}_var").set(text)
        except queue.Empty:
            pass
        self.after(100, self.process_events)

    def save_settings(self) -> None:
        data = {
            "raw_base": self.raw_var.get().strip(),
            "repo": self.repo_var.get().strip(),
            "binary": self.binary_var.get().strip(),
            "server_addr": self.server_var.get().strip(),
            "server_port": self.server_port_var.get().strip(),
            "temp_port": self.temp_port_var.get().strip(),
            "tls_server_name": self.tls_name_var.get().strip(),
            "ssh_dir": self.ssh_dir_var.get().strip(),
            "key_name": self.key_name_var.get().strip(),
        }
        try:
            target = settings_path()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass

    def validate_inputs(self) -> tuple[str, Optional[int], str]:
        raw = normalize_raw_base(self.raw_var.get())
        port_text = self.temp_port_var.get().strip()
        port: Optional[int] = None
        if port_text:
            try:
                port = int(port_text)
            except ValueError as exc:
                raise AppError("临时远端端口必须是 1-65535 的数字，或留空自动选择。") from exc
            if not 1 <= port <= 65535:
                raise AppError("临时远端端口必须在 1-65535 范围内。")
        password = self.password_entry.get()
        if not password:
            raise AppError("请输入密钥传输密码。")
        key_name = self.key_name_var.get().strip() or KEY_NAME_DEFAULT
        if not KEY_NAME_RE.fullmatch(key_name):
            raise AppError("SSH 密钥名只能包含字母、数字、点、下划线和连字符。")
        return raw, port, password

    def start(self) -> None:
        if self.worker is not None:
            return
        try:
            raw, temp_port, password = self.validate_inputs()
        except AppError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.save_settings()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.hide_command_controls()
        self.proxy_ready = False
        self.current_token = ""
        self.current_url = ""
        self.current_command = ""
        self.status_var.set("正在准备加密载荷…")
        self.log("启动临时通道；密码只保存在本次进程内存和临时文件中。")
        options = RunOptions(
            raw_base=raw,
            temp_port=temp_port,
            repo=self.repo_var.get().strip(),
            binary=self.binary_var.get().strip(),
            server_addr=self.server_var.get().strip(),
            server_port=self.server_port_var.get().strip(),
            tls_server_name=self.tls_name_var.get().strip(),
            ssh_dir=self.ssh_dir_var.get().strip(),
            key_name=self.key_name_var.get().strip() or KEY_NAME_DEFAULT,
        )
        self.worker_thread = threading.Thread(
            target=self.prepare_and_start,
            args=(options, password),
            daemon=True,
        )
        self.worker_thread.start()
        self.password_entry.delete(0, "end")

    def prepare_and_start(self, options: RunOptions, password: str) -> None:
        temp_root = pathlib.Path(tempfile.mkdtemp(prefix="fpro-delivery-gui-"))
        self.temp_root = temp_root
        try:
            repo = pathlib.Path(options.repo).expanduser() if options.repo else pathlib.Path()
            config_source = repo / CONFIG_ARTIFACT
            if not config_source.is_file():
                config_source = temp_root / CONFIG_ARTIFACT
                download_file(options.raw_base + "/" + CONFIG_ARTIFACT, config_source, log=lambda s: self.post("log", s))
            else:
                self.post("log", f"使用本地加密配置：{config_source.name}")
            self.post("log", "解密配置载荷并读取服务参数…")
            config_bytes = decrypt_file(config_source, password, max_bytes=MAX_CONFIG_BYTES)
            payload = extract_payload(config_bytes, temp_root / "payload")
            values = config_values(payload / "fpro-client.toml")

            server_addr = options.server_addr or values["server_addr"]
            server_port_text = options.server_port or values["server_port"] or "7000"
            tls_name = options.tls_server_name or values["tls_server_name"] or server_addr
            if not server_addr:
                raise AppError("无法从加密配置读取服务端地址，请在高级设置中填写。")
            try:
                server_port = int(server_port_text)
            except ValueError as exc:
                raise AppError("fpro 控制端口不是有效数字。") from exc
            if not 1 <= server_port <= 65535:
                raise AppError("fpro 控制端口必须在 1-65535 范围内。")

            binary = self.resolve_binary(
                repo,
                options.raw_base,
                password,
                temp_root,
                selected=options.binary,
                log=lambda s: self.post("log", s),
            )
            receiver_token_value = secrets.token_urlsafe(32)
            receiver_token = temp_root / "receiver-token"
            write_private(receiver_token, receiver_token_value + "\n")
            package_password = temp_root / "package-password"
            write_private(package_password, password)
            fpro_token = payload / "certs" / "auth-token"

            ssh_port: Optional[int] = None
            try:
                if values["remote_port"]:
                    candidate = int(values["remote_port"])
                    if 1 <= candidate <= 65535:
                        ssh_port = candidate
            except ValueError:
                pass
            temp_port = select_temp_port(options.temp_port, ssh_port)
            self.post("set", ("temp_port", str(temp_port)))
            assets = PreparedAssets(
                temp_root=temp_root,
                binary=binary,
                client_crt=payload / "certs" / "client.crt",
                client_key=payload / "certs" / "client.key",
                ca_crt=payload / "certs" / "ca.crt",
                fpro_token=fpro_token,
                package_password=package_password,
                receiver_token=receiver_token,
                receiver_token_value=receiver_token_value,
                server_addr=server_addr,
                server_port=server_port,
                tls_server_name=tls_name,
                fpro_user=values.get("user", ""),
                key_name=options.key_name,
                ssh_port=ssh_port,
                remote_port=temp_port,
                raw_base=options.raw_base,
            )
            self.prepared = assets
            self.current_token = receiver_token_value
            preview_url = f"http://{url_host(server_addr)}:{temp_port}/v1/ssh-key"
            self.post(
                "command_preview",
                make_remote_command(options.raw_base, preview_url, options.key_name),
            )
            self.post("set", ("server", server_addr))
            self.post("set", ("server_port", str(server_port)))
            self.post("set", ("tls_name", tls_name))
            self.post("log", f"使用 Windows 架构客户端：{binary.name}")

            receiver_args = [
                "proxy",
                "--fpro-binary",
                str(binary),
                "--server-addr",
                server_addr,
                "--server-port",
                str(server_port),
                "--remote-port",
                str(temp_port),
                "--tls-cert",
                str(assets.client_crt),
                "--tls-key",
                str(assets.client_key),
                "--tls-ca",
                str(assets.ca_crt),
                "--tls-server-name",
                tls_name,
                "--token-file",
                str(receiver_token),
                "--fpro-token-file",
                str(fpro_token),
                "--password-file",
                str(package_password),
                "--ssh-dir",
                options.ssh_dir or str(pathlib.Path.home() / ".ssh"),
                "--key-name",
                options.key_name,
                "--no-key-passphrase-prompt",
                "--response-grace",
                "3",
            ]
            if assets.fpro_user:
                receiver_args.extend(["--fpro-user", assets.fpro_user])
            if assets.ssh_port:
                receiver_args.extend(["--ssh-host", server_addr, "--ssh-port", str(assets.ssh_port)])
            command = worker_command(receiver_args)
            self.post("status", "正在建立一次性 fpro 通道…")
            self.post("log", "启动本机接收器和临时 fpro 客户端…")
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            worker_env = os.environ.copy()
            # The host may still be using CP936 (the default on many Windows
            # installations).  The receiver emits UTF-8 over this pipe, so
            # make that contract explicit and keep output unbuffered.
            worker_env["PYTHONIOENCODING"] = "utf-8"
            worker_env["PYTHONUTF8"] = "1"
            worker_env["PYTHONUNBUFFERED"] = "1"
            self.worker = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                env=worker_env,
                creationflags=creationflags,
            )
            threading.Thread(target=self.read_worker, args=(self.worker,), daemon=True).start()
        except (AppError, CryptoError, OSError, ValueError) as exc:
            self.post("error", str(exc))

    def resolve_binary(
        self,
        repo: pathlib.Path,
        raw: str,
        password: str,
        temp_root: pathlib.Path,
        *,
        selected: str,
        log: Callable[[str], None],
    ) -> pathlib.Path:
        if selected:
            source = pathlib.Path(selected).expanduser()
            if not source.is_file():
                raise AppError(f"找不到指定的 fpro-client：{source}")
            if source.suffix.lower() == ".enc":
                output = temp_root / windows_binary_name()
                output.write_bytes(decrypt_file(source, password, max_bytes=MAX_CONFIG_BYTES))
                return validate_windows_binary(output)
            return validate_windows_binary(source.resolve())

        name = windows_binary_name()
        local_candidates = [repo / name, repo / f"{name}.enc"] if repo else []
        for source in local_candidates:
            if source.is_file():
                if source.suffix.lower() == ".enc":
                    log(f"解密本地 {source.name} …")
                    output = temp_root / name
                    output.write_bytes(decrypt_file(source, password, max_bytes=MAX_CONFIG_BYTES))
                    return validate_windows_binary(output)
                return validate_windows_binary(source.resolve())
        encrypted = temp_root / f"{name}.enc"
        download_file(raw + "/" + encrypted.name, encrypted, log=log)
        log(f"解密 {name} …")
        output = temp_root / name
        output.write_bytes(decrypt_file(encrypted, password, max_bytes=MAX_CONFIG_BYTES))
        return validate_windows_binary(output)

    def read_worker(self, process: subprocess.Popen[bytes]) -> None:
        try:
            if process.stdout is not None:
                for raw_line in process.stdout:
                    line = decode_worker_line(raw_line)
                    ready = WORKER_READY_MARKER in line or "临时 fpro 通道已建立" in line
                    # Do not expose the protocol marker in the human log.
                    line = line.replace(WORKER_READY_MARKER, "").strip()
                    if line:
                        self.post("log", line)
                    if ready:
                        self.post("ready")
            code = process.wait()
        except OSError as exc:
            self.post("error", f"接收器进程异常：{exc}")
            return
        self.post("done", code)

    def on_proxy_ready(self) -> None:
        if self.proxy_ready or self.prepared is None:
            return
        self.proxy_ready = True
        assets = self.prepared
        self.current_url = f"http://{url_host(assets.server_addr)}:{assets.remote_port}/v1/ssh-key"
        command = make_remote_command(assets.raw_base, self.current_url, assets.key_name)
        self.current_command = command
        self.set_command_preview(command)
        self.clipboard_clear()
        self.clipboard_append(command)
        self.update()
        self.show_command_controls()
        self.status_var.set("临时通道已建立，请在 Cloud Studio 终端执行安装命令")
        self.log("临时通道已建立；bash 命令已显示并复制到剪贴板。")
        self.log("请把命令粘贴到 Cloud Studio 终端并回车，按提示输入密码和一次性 token。")

    def copy_command(self) -> None:
        if not self.current_command:
            return
        self.clipboard_clear()
        self.clipboard_append(self.current_command)
        self.update()
        self.log("bash 命令已复制。")

    def copy_token(self) -> None:
        if not self.current_token:
            return
        self.clipboard_clear()
        self.clipboard_append(self.current_token)
        self.update()
        self.log("一次性 token 已复制；仅在 Cloud Studio 的 token 提示处粘贴。")

    def on_worker_done(self, code: int) -> None:
        self.worker = None
        self.stop_button.configure(state="disabled")
        self.start_button.configure(state="normal")
        self.hide_command_controls()
        if code == 0:
            self.status_var.set("完成：SSH 私钥已写入本机")
            self.log("一次性通道已关闭；SSH 私钥已写入本机，请使用日志中的路径连接实际 SSH 映射端口。")
        else:
            self.status_var.set("失败：请查看日志")
            self.log(f"接收器退出码：{code}")
        self.cleanup_temp()

    def on_error(self, message: str) -> None:
        self.status_var.set("失败：请查看日志")
        self.log("错误：" + message)
        self.stop()
        messagebox.showerror(APP_NAME, message)

    def stop(self) -> None:
        process = self.worker
        self.worker = None
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
        self.stop_button.configure(state="disabled")
        self.start_button.configure(state="normal")
        self.hide_command_controls()
        self.cleanup_temp()

    def cleanup_temp(self) -> None:
        root = self.temp_root
        self.temp_root = None
        self.prepared = None
        self.current_token = ""
        self.current_url = ""
        self.current_command = ""
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)

    def on_close(self) -> None:
        self.save_settings()
        self.stop()
        self.destroy()


def run_worker(argv: list[str]) -> int:
    """Hidden entry point used by the packaged executable's child process."""
    try:
        import fpro_ssh_receiver
    except ImportError:  # pragma: no cover
        from . import fpro_ssh_receiver
    return fpro_ssh_receiver.main(argv)


def self_test() -> int:
    """Non-GUI smoke checks used by the build/CI script."""
    assert windows_binary_name().startswith("fpro-client_windows_")
    assert select_temp_port(None, 7022) == 7023
    assert select_temp_port(None, 22) == DEFAULT_TEMP_PORT_MIN
    assert select_temp_port(8123, 7022) == 8123
    command = make_remote_command(DEFAULT_RAW_BASE, "http://example.invalid:12345/v1/ssh-key")
    assert "FPRO_SSH_RECEIVER_TOKEN_FILE" in command
    assert "FPRO_PACKAGE_PASSWORD_FILE" in command
    assert "mktemp" in command and "trap 'rm -f" in command
    assert "FPRO package password" in command
    assert "FPRO one-time transfer token" in command
    assert "automate_cloudstudio" not in command
    assert "example.invalid" in command
    assert decode_worker_line("临时 fpro 通道已建立".encode("gb18030")) == "临时 fpro 通道已建立"
    assert decode_worker_line(WORKER_READY_MARKER.encode("ascii")) == WORKER_READY_MARKER
    named_command = make_remote_command(
        DEFAULT_RAW_BASE,
        "http://example.invalid:12345/v1/ssh-key",
        "custom_key-01",
    )
    assert "FPRO_SSH_KEY_NAME='custom_key-01'" in named_command
    try:
        make_remote_command(DEFAULT_RAW_BASE, "http://example.invalid:12345/v1/ssh-key", "bad/name")
    except AppError:
        pass
    else:
        raise AssertionError("invalid SSH key name was accepted")
    print("fpro_delivery_gui self-test PASS")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--receiver-worker" in args:
        index = args.index("--receiver-worker")
        return run_worker(args[index + 1 :])
    if "--self-test" in args:
        return self_test()
    if tk is None:
        print("当前 Python 没有 tkinter，无法启动 Windows GUI。", file=sys.stderr)
        return 2
    app = DeliveryApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
