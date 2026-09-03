"""Small OpenSSL ``enc -aes-256-cbc -pbkdf2`` compatibility layer.

The repository payloads are encrypted with OpenSSL's salted file format.  The
normal command-line tools can still be used, but the Windows one-click app
must not depend on a separately installed ``openssl.exe``.  When the
``cryptography`` package is available (it is bundled into the packaged app),
decryption happens in-process; otherwise the helper falls back to the local
OpenSSL executable.
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess
import tempfile
from typing import Callable, Optional


class CryptoError(RuntimeError):
    """Raised when an encrypted artifact cannot be decrypted."""


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise CryptoError("解密结果为空。")
    padding = data[-1]
    if padding < 1 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise CryptoError("密码错误或加密文件损坏。")
    return data[:-padding]


def _python_decrypt(payload: bytes, password: str) -> bytes:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as exc:
        raise CryptoError("当前 Python 没有 cryptography 模块。") from exc

    if len(payload) < 16 or payload[:8] != b"Salted__":
        raise CryptoError("不是受支持的 OpenSSL salted 加密文件。")
    salt = payload[8:16]
    ciphertext = payload[16:]
    if not ciphertext or len(ciphertext) % 16:
        raise CryptoError("加密文件长度无效。")

    # OpenSSL enc -pbkdf2 defaults to 10,000 iterations and SHA-256 in the
    # OpenSSL versions used to create this repository.  SHA-1 is retained as
    # a compatibility fallback for older artifacts made with an explicit
    # legacy digest setting.
    last_error: Optional[Exception] = None
    for digest in (hashes.SHA256(), hashes.SHA1()):
        try:
            kdf = PBKDF2HMAC(
                algorithm=digest,
                length=48,
                salt=salt,
                iterations=10_000,
            )
            key_iv = kdf.derive(password.encode("utf-8"))
            decryptor = Cipher(
                algorithms.AES(key_iv[:32]), modes.CBC(key_iv[32:])
            ).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return _pkcs7_unpad(plaintext)
        except Exception as exc:  # try the compatibility digest next
            last_error = exc
    raise CryptoError("密码错误或加密文件损坏。") from last_error


def decrypt_bytes(payload: bytes, password: str) -> bytes:
    """Decrypt OpenSSL salted bytes, preferring in-process crypto."""
    if not password:
        raise CryptoError("解密密码不能为空。")
    try:
        return _python_decrypt(payload, password)
    except CryptoError as python_error:
        # If the failure was a genuine padding/password error and OpenSSL is
        # available, let OpenSSL make the final compatibility attempt.  This
        # also covers artifacts using a digest not supported by the fallback.
        openssl = shutil.which("openssl")
        if not openssl:
            raise
        temporary_name: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(prefix="fpro-enc-", suffix=".bin", delete=False) as stream:
                stream.write(payload)
                temporary_name = stream.name
            result = subprocess.run(
                [
                    openssl,
                    "enc",
                    "-d",
                    "-aes-256-cbc",
                    "-pbkdf2",
                    "-in",
                    temporary_name,
                    "-pass",
                    "stdin",
                ],
                input=(password + "\n").encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as exc:
            raise python_error from exc
        finally:
            if temporary_name:
                try:
                    pathlib.Path(temporary_name).unlink()
                except OSError:
                    pass
        if result.returncode == 0:
            return result.stdout
        raise python_error


def decrypt_file(path: pathlib.Path, password: str, *, max_bytes: int = 512 * 1024 * 1024) -> bytes:
    """Read and decrypt one file with a bounded input size."""
    try:
        size = path.stat().st_size
        if size < 1 or size > max_bytes:
            raise CryptoError("加密文件不存在或超过大小限制。")
        payload = path.read_bytes()
    except OSError as exc:
        raise CryptoError(f"读取加密文件失败：{exc}") from exc
    return decrypt_bytes(payload, password)
