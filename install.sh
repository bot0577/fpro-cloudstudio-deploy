#!/usr/bin/env bash
# ============================================================================
#  fpro 一键部署脚本 (Cloud Studio 容器侧)
# ----------------------------------------------------------------------------
#  功能：
#   1) 提示输入压缩包解压密码（密码错误则拒绝继续，不会落地任何文件）
#   2) 解密并解包加密压缩包（AES-256-CBC + PBKDF2）
#   3) 结束此前部署的全部 fpro-client 进程（精确匹配，避免误杀自身）
#   4) 安装 fpro-client 二进制、证书、auth-token、客户端配置
#   5) 配置并拉起 sshd（root 密钥登录，关闭密码登录）
#   6) 拉起看门狗，自动上线到 [REDACTED_HOST]:7022
#   7) 自检隧道是否打通
#
#  使用（容器重启后）：
#    bash install.sh            # 默认读取同目录下的 fpro-deploy.tar.gz.enc
#    或：
#    PKG_URL=https://.../raw/.../fpro-deploy.tar.gz.enc bash install.sh
# ============================================================================

set -Eeuo pipefail
umask 077

on_error() {
    local rc=$?
    echo "[-] 安装失败（脚本第 ${BASH_LINENO[0]:-?} 行，exit=${rc}）。" >&2
    exit "$rc"
}
trap on_error ERR

PKG_NAME="fpro-deploy.tar.gz.enc"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_INPUT="${PKG_URL:-$DIR/$PKG_NAME}"

# ---- 0. 权限 & 依赖检查 ----------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] 请用 root 运行： sudo bash install.sh" >&2
    exit 1
fi
for c in openssl tar mktemp; do
    command -v "$c" >/dev/null 2>&1 || { echo "[-] 缺少依赖: $c" >&2; exit 1; }
done

# 临时目录既用于下载，也用于解密/解包；退出时无条件清理。
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP" 2>/dev/null || true; }
trap cleanup EXIT

# PKG_URL 支持 HTTPS 下载；未设置时读取脚本同目录的本地文件。
if [[ "$PKG_INPUT" == https://* ]]; then
    PKG="$TMP/$PKG_NAME"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --proto '=https' \
            --tlsv1.2 "$PKG_INPUT" -o "$PKG"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --quiet -O "$PKG" "$PKG_INPUT"
    else
        echo "[-] 使用 PKG_URL 时需要 curl 或 wget。" >&2
        exit 1
    fi
elif [[ "$PKG_INPUT" == *://* ]]; then
    echo "[-] PKG_URL 只支持 HTTPS URL。" >&2
    exit 1
else
    PKG="$PKG_INPUT"
    if [ ! -f "$PKG" ]; then
        echo "[-] 找不到加密压缩包: $PKG" >&2
        echo "    请把 install.sh 与 $PKG_NAME 放在同一目录，或用 PKG_URL 指定 HTTPS 地址。" >&2
        exit 1
    fi
fi

# ---- 1. 输入密码 ----------------------------------------------------------
echo "=========================================================="
echo "  fpro 一键部署 — 请输入压缩包解压密码"
echo "=========================================================="
read -r -s -p "解压密码: " PASS
echo
if [ -z "$PASS" ]; then
    echo "[-] 密码为空，已取消。" >&2
    exit 1
fi

# ---- 2. 解密（密码错则立即失败，不落地） -----------------------------------
echo "[*] 校验密码并解密压缩包 ..."
if ! printf '%s\n' "$PASS" | openssl enc -d -aes-256-cbc -pbkdf2 \
        -in "$PKG" -out "$TMP/payload.tar.gz" -pass stdin 2>/dev/null; then
    echo "[-] 密码错误或未识别的压缩包，解密失败。已中止，未写入任何文件。" >&2
    exit 1
fi
if ! tar -xzf "$TMP/payload.tar.gz" -C "$TMP" 2>/dev/null; then
    echo "[-] 解包失败，压缩包可能已损坏。" >&2
    exit 1
fi
# 兼容两种包布局：当前 README 生成的是顶层 bin/certs/...，旧包可能
# 包在 payload/ 目录下。先确定根目录，再校验所有必需文件，避免继续执行
# 一个已经不完整的安装。
if [ -d "$TMP/payload" ]; then
    PAY="$TMP/payload"
else
    PAY="$TMP"
fi
required_files=(
    "bin/fpro-client_linux_amd64"
    "certs/ca.crt"
    "certs/client.crt"
    "certs/client.key"
    "fpro-client.toml"
    "watchdog.sh"
    "ssh/authorized_keys"
    "sshd_config.d/90-ragp.conf"
)
for rel in "${required_files[@]}"; do
    if [ ! -f "$PAY/$rel" ]; then
        echo "[-] 载荷缺少必需文件: $rel" >&2
        exit 1
    fi
done
echo "[+] 解密成功，载荷已就绪。"

# ---- 3. 结束此前的 fpro-client 进程（精确匹配 /proc/<pid>/exe） -----------
echo "[*] 清理既有 fpro-client 进程 ..."
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    case "$exe" in
        */fpro-client) kill "$pid" 2>/dev/null && echo "    终止旧进程 pid=$pid" ;;
    esac
done
sleep 1
# 兜底：用进程名精确匹配再清一次
pkill -x fpro-client 2>/dev/null || true
# 同时停掉旧的看门狗，避免重复拉起
pkill -f "fpro-client/watchdog.sh" 2>/dev/null || true
sleep 1

# ---- 4. 安装 fpro-client 二进制 / 证书 / 配置 ------------------------------
echo "[*] 安装 fpro-client 二进制与证书 ..."
install -m 0755 "$PAY/bin/fpro-client_linux_amd64" /usr/local/bin/fpro-client
mkdir -p /opt/fpro-client/certs
cp "$PAY/certs/ca.crt"     /opt/fpro-client/certs/ca.crt
cp "$PAY/certs/client.crt" /opt/fpro-client/certs/client.crt
cp "$PAY/certs/client.key" /opt/fpro-client/certs/client.key
cp "$PAY/fpro-client.toml" /opt/fpro-client/fpro-client.toml
install -m 0755 "$PAY/watchdog.sh" /opt/fpro-client/watchdog.sh
chmod 644 /opt/fpro-client/certs/ca.crt /opt/fpro-client/certs/client.crt
chmod 600 /opt/fpro-client/certs/client.key
echo "[+] 二进制: $(fpro-client --version 2>&1 | head -1 || echo unknown)"

# ---- 5. 配置 sshd ---------------------------------------------------------
echo "[*] 配置 sshd (root 密钥登录 / 关闭密码登录) ..."
mkdir -p /root/.ssh && chmod 700 /root/.ssh
if ! grep -qF "$(cat "$PAY/ssh/authorized_keys")" /root/.ssh/authorized_keys 2>/dev/null; then
    cat "$PAY/ssh/authorized_keys" >> /root/.ssh/authorized_keys
fi
chmod 600 /root/.ssh/authorized_keys
mkdir -p /etc/ssh/sshd_config.d
cp "$PAY/sshd_config.d/90-ragp.conf" /etc/ssh/sshd_config.d/90-ragp.conf
chmod 644 /etc/ssh/sshd_config.d/90-ragp.conf

# 确保 sshd 存在；缺失则尝试安装（容器通常已带 openssh-server）
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
    echo "    [!] 未找到 sshd，尝试 apt-get 安装 ..."
    apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq openssh-server >/dev/null 2>&1 \
        || echo "    [!] 自动安装失败，请手动安装 openssh-server 后重跑本脚本。"
fi
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
if [ ! -x "$SSHD_BIN" ]; then
    echo "[-] 找不到可执行的 sshd。" >&2
    exit 1
fi

mkdir -p /run/sshd
if ! "$SSHD_BIN" -t; then
    echo "[-] sshd 配置校验失败，未启动 sshd。" >&2
    exit 1
fi
if ! pgrep -x sshd >/dev/null 2>&1; then
    "$SSHD_BIN" && echo "[+] sshd 已启动" || echo "[!] sshd 启动失败，请检查 sshd 配置"
else
    echo "[+] sshd 已在运行"
fi

# ---- 6. 拉起看门狗（自动上线 220:7022） ------------------------------------
echo "[*] 启动 fpro-client 看门狗 ..."
nohup /opt/fpro-client/watchdog.sh >>/var/log/fpro-watchdog.log 2>&1 &
watchdog_pid=$!
sleep 4
if ! kill -0 "$watchdog_pid" 2>/dev/null; then
    echo "[-] 看门狗启动失败，请查看 /var/log/fpro-watchdog.log" >&2
    exit 1
fi

# ---- 7. 自检 --------------------------------------------------------------
echo "[*] 自检 ..."
if pgrep -x fpro-client >/dev/null 2>&1; then
    echo "[+] fpro-client 进程存活"
else
    echo "[-] fpro-client 未运行，查看日志: tail -n 20 /var/log/fpro-client.log" >&2
    exit 1
fi

# 回环验证：容器 -> 220:7022 -> 容器:22
if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=6 -o BatchMode=yes \
       -p 7022 root@[REDACTED_HOST] 'echo TUNNEL_OK' 2>/dev/null | grep -q TUNNEL_OK; then
    echo "[+] 隧道已打通：ssh -p 7022 root@[REDACTED_HOST] 可用"
else
    echo "[-] 隧道回环自检未通过（进程可能还在握手），请稍后重试：" >&2
    echo "      ssh -p 7022 root@[REDACTED_HOST]"
    exit 1
fi

echo "=========================================================="
echo "  部署完成。"
echo "  本机连接命令： ssh -p 7022 root@[REDACTED_HOST]"
echo "=========================================================="
