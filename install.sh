#!/usr/bin/env bash
# ============================================================================
#  fpro 一键部署脚本 (Cloud Studio 容器侧)
# ----------------------------------------------------------------------------
#  功能：
#   1) 提示输入压缩包解压密码（密码错误则拒绝继续，不会落地任何文件）
#   2) 解密并解包加密压缩包（AES-256-CBC + PBKDF2）
#   3) 结束此前部署的全部 fpro-client 进程（精确匹配，避免误杀自身）
#   4) 按当前 Linux 架构下载并解密对应的 fpro-client 二进制，安装证书与配置
#   5) 配置并拉起 sshd（root 密钥登录，关闭密码登录）
#   6) 拉起看门狗，按加密配置连接服务端
#   7) 从加密配置读取映射地址并自检隧道
#
#  使用（容器重启后）：
#    bash install.sh             # 本地文件存在时使用本地文件，否则从 GitHub Raw 下载
#    curl -fsSL https://raw.githubusercontent.com/bot0577/fpro-cloudstudio-deploy/main/install.sh | sudo bash
#    或通过 PKG_URL / BINARY_BASE_URL 覆盖默认下载地址
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
RAW_BASE_URL="${FPRO_REPO_RAW_BASE_URL:-https://raw.githubusercontent.com/bot0577/fpro-cloudstudio-deploy/main}"
RAW_BASE_URL="${RAW_BASE_URL%/}"
SCRIPT_REF="${BASH_SOURCE[0]:-}"
if [ -n "$SCRIPT_REF" ] && [ -f "$SCRIPT_REF" ]; then
    DIR="$(cd "$(dirname "$SCRIPT_REF")" && pwd)"
else
    # curl | bash / bash <(curl ...) 没有可用的脚本目录；使用当前目录仅作本地回退。
    DIR="$(pwd)"
fi
if [ -n "${PKG_URL:-}" ]; then
    PKG_INPUT="$PKG_URL"
elif [ -f "$DIR/$PKG_NAME" ]; then
    PKG_INPUT="$DIR/$PKG_NAME"
else
    PKG_INPUT="$RAW_BASE_URL/$PKG_NAME"
fi

die() {
    echo "[-] $*" >&2
    exit 1
}

[[ "$RAW_BASE_URL" == https://* ]] || die "FPRO_REPO_RAW_BASE_URL 必须使用 HTTPS。"

download_artifact() {
    local source="$1"
    local dest="$2"
    local github_token="${FPRO_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
    local -a auth_args=()
    # 私有仓库可通过环境变量提供只读令牌；令牌不写入文件或 URL。
    if [ -n "$github_token" ] && [[ "$source" == https://raw.githubusercontent.com/* ]]; then
        auth_args=(--header "Authorization: Bearer $github_token")
    fi
    if [[ "$source" == https://* ]]; then
        if command -v curl >/dev/null 2>&1; then
            if ! curl --fail --location --silent --show-error --proto '=https' \
                    --tlsv1.2 "${auth_args[@]}" "$source" -o "$dest"; then
                die "下载失败：$source。私有 GitHub 仓库请配置 FPRO_GITHUB_TOKEN，或先进行稀疏克隆。"
            fi
        elif command -v wget >/dev/null 2>&1; then
            if ! wget --https-only --quiet "${auth_args[@]}" -O "$dest" "$source"; then
                die "下载失败：$source。私有 GitHub 仓库请配置 FPRO_GITHUB_TOKEN，或先进行稀疏克隆。"
            fi
        else
            die "从 HTTPS 下载文件需要 curl 或 wget。"
        fi
    elif [[ "$source" == *://* ]]; then
        die "只支持本地路径或 HTTPS URL：$source"
    else
        [ -f "$source" ] || die "找不到文件：$source"
        cp "$source" "$dest"
    fi
}

detect_client_binary() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    [ "$os" = "Linux" ] || die "当前安装脚本只支持 Linux，检测到：$os"
    case "$arch" in
        x86_64|amd64) echo "fpro-client_linux_amd64.b64" ;;
        aarch64|arm64) echo "fpro-client_linux_arm64.b64" ;;
        armv5*|armv6*|arm5*) echo "fpro-client_linux_arm_armv5.b64" ;;
        armv7*|armhf|arm) echo "fpro-client_linux_arm_armv7.b64" ;;
        loongarch64) echo "fpro-client_linux_loong64.b64" ;;
        riscv64) echo "fpro-client_linux_riscv64.b64" ;;
        mips64el|mips64le) echo "fpro-client_linux_mips64le.b64" ;;
        mips64) echo "fpro-client_linux_mips64.b64" ;;
        mipsel) echo "fpro-client_linux_mipsle_softfloat.b64" ;;
        mips) echo "fpro-client_linux_mips_softfloat.b64" ;;
        *) die "没有适配当前 Linux 架构 ($arch) 的 fpro-client。可用 FPRO_BINARY_NAME 手动指定。" ;;
    esac
}

resolve_binary_source() {
    local pkg_no_query pkg_dir
    if [ -n "${FPRO_BINARY_URL:-}" ]; then
        printf '%s\n' "$FPRO_BINARY_URL"
    elif [ -n "${BINARY_BASE_URL:-}" ]; then
        printf '%s/%s\n' "${BINARY_BASE_URL%/}" "$BINARY_ENC_NAME"
    elif [[ "$PKG_INPUT" == https://* ]]; then
        pkg_no_query="${PKG_INPUT%%\?*}"
        printf '%s/%s\n' "${pkg_no_query%/*}" "$BINARY_ENC_NAME"
    else
        pkg_dir="$(dirname "$PKG_INPUT")"
        printf '%s/%s\n' "$pkg_dir" "$BINARY_ENC_NAME"
    fi
}

read_toml_scalar() {
    local key="$1"
    local file="$2"
    local line value
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*${key}[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            value="${BASH_REMATCH[1]}"
            value="${value%%#*}"
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            if [[ "$value" == \"*\" ]]; then
                value="${value#\"}"
                value="${value%%\"*}"
            fi
            printf '%s\n' "$value"
            return 0
        fi
    done < "$file"
    return 1
}

CLIENT_PLAIN_NAME="${FPRO_BINARY_NAME:-$(detect_client_binary)}"
if [[ "$CLIENT_PLAIN_NAME" == *.enc ]]; then
    CLIENT_PLAIN_NAME="${CLIENT_PLAIN_NAME%.enc}"
fi
[[ "$CLIENT_PLAIN_NAME" == fpro-client_* ]] || die "FPRO_BINARY_NAME 必须是 fpro-client 平台文件名。"
[[ "$CLIENT_PLAIN_NAME" != */* ]] || die "FPRO_BINARY_NAME 不得包含目录路径。"
BINARY_ENC_NAME="${CLIENT_PLAIN_NAME}.enc"

# ---- 0. 权限 & 依赖检查 ----------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] 请用 root 运行： sudo bash install.sh" >&2
    exit 1
fi
for c in openssl tar mktemp base64 uname; do
    command -v "$c" >/dev/null 2>&1 || { echo "[-] 缺少依赖: $c" >&2; exit 1; }
done

# 临时目录既用于下载，也用于解密/解包；退出时无条件清理。
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP" 2>/dev/null || true; }
trap cleanup EXIT

# PKG_URL 支持 HTTPS 下载；未设置时优先使用同目录文件，否则使用默认 GitHub Raw 地址。
PKG="$TMP/$PKG_NAME"
download_artifact "$PKG_INPUT" "$PKG"

# ---- 1. 输入密码 ----------------------------------------------------------
echo "=========================================================="
echo "  fpro 一键部署 — 请输入压缩包解压密码"
echo "=========================================================="
if [ -t 0 ]; then
    read -r -s -p "解压密码: " PASS
elif [ -r /dev/tty ]; then
    # 支持 curl | sudo bash：脚本内容占用 stdin，密码改从控制终端读取。
    read -r -s -p "解压密码: " PASS < /dev/tty
else
    die "需要交互式终端输入解压密码；请在 TTY 中运行脚本。"
fi
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

# ---- 2b. 按架构获取独立加密二进制 ------------------------------------------
# 新方案：每个平台文件单独以原文件名 + .enc 存放在仓库中。
# 兼容旧包：若配置包仍携带 amd64 原始二进制，则仅在对应架构下回退使用。
FPRO_BIN=""
legacy_binary="$PAY/bin/fpro-client_linux_amd64"
if [ -f "$legacy_binary" ] && [ "$CLIENT_PLAIN_NAME" = "fpro-client_linux_amd64.b64" ]; then
    echo "[*] 检测到旧版载荷内置 amd64 二进制，兼容使用。"
    FPRO_BIN="$legacy_binary"
else
    BINARY_SOURCE="$(resolve_binary_source)"
    echo "[*] 获取架构二进制：$BINARY_ENC_NAME"
    download_artifact "$BINARY_SOURCE" "$TMP/$BINARY_ENC_NAME"
    CLIENT_PLAIN="$TMP/$CLIENT_PLAIN_NAME"
    if ! printf '%s\n' "$PASS" | openssl enc -d -aes-256-cbc -pbkdf2 \
            -in "$TMP/$BINARY_ENC_NAME" -out "$CLIENT_PLAIN" -pass stdin 2>/dev/null; then
        echo "[-] 二进制解密失败：$BINARY_ENC_NAME（密码错误或文件损坏）。" >&2
        exit 1
    fi
    if [[ "$CLIENT_PLAIN_NAME" == *.b64 ]]; then
        FPRO_BIN="$TMP/fpro-client"
        if ! base64 -d "$CLIENT_PLAIN" > "$FPRO_BIN" 2>/dev/null; then
            echo "[-] 二进制 Base64 解码失败：$CLIENT_PLAIN_NAME" >&2
            exit 1
        fi
    else
        FPRO_BIN="$CLIENT_PLAIN"
    fi
fi
[ -s "$FPRO_BIN" ] || die "架构二进制为空或不存在：$FPRO_BIN"
unset PASS

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
install -m 0755 "$FPRO_BIN" /usr/local/bin/fpro-client
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

# ---- 6. 拉起看门狗 ---------------------------------------------------------
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

# 回环验证所需的地址和端口从解密后的客户端配置读取，避免写入仓库明文。
TUNNEL_HOST="${FPRO_TUNNEL_HOST:-$(read_toml_scalar serverAddr "$PAY/fpro-client.toml" || true)}"
TUNNEL_PORT="${FPRO_TUNNEL_PORT:-$(read_toml_scalar remotePort "$PAY/fpro-client.toml" || true)}"
[ -n "$TUNNEL_HOST" ] || die "无法从加密配置读取 serverAddr。"
[[ "$TUNNEL_PORT" =~ ^[0-9]+$ ]] || die "无法从加密配置读取有效的 remotePort。"
[[ "$TUNNEL_HOST" =~ ^[A-Za-z0-9._:-]+$ ]] || die "加密配置中的 serverAddr 格式无效。"

# 如果调用方提供了对应的 SSH 私钥，则执行完整的登录验证。密钥不属于
# 部署载荷，也不会被写入仓库；通过 FPRO_TUNNEL_SSH_KEY 临时传入即可。
declare -a SSH_SELFTEST_ARGS=()
if [ -n "${FPRO_TUNNEL_SSH_KEY:-}" ]; then
    [ -f "$FPRO_TUNNEL_SSH_KEY" ] || die "FPRO_TUNNEL_SSH_KEY 不存在：$FPRO_TUNNEL_SSH_KEY"
    SSH_SELFTEST_ARGS=(-i "$FPRO_TUNNEL_SSH_KEY" -o IdentitiesOnly=yes)
fi

# 没有私钥时，ssh 仍会完成 TCP/SSH 握手并返回 publickey 认证提示。将这种
# 情况视为“隧道端口已响应但无法在容器内完成登录”，避免 Cloud Studio 等
# 没有用户私钥的环境被误报为安装失败；其它连接错误仍然使安装失败。
TUNNEL_TEST_OUT="$TMP/tunnel-selftest.out"
TUNNEL_TEST_ERR="$TMP/tunnel-selftest.err"
ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=6 -o BatchMode=yes \
    "${SSH_SELFTEST_ARGS[@]}" -p "$TUNNEL_PORT" "root@$TUNNEL_HOST" \
    'echo TUNNEL_OK' >"$TUNNEL_TEST_OUT" 2>"$TUNNEL_TEST_ERR" || true
if grep -qx 'TUNNEL_OK' "$TUNNEL_TEST_OUT"; then
    echo "[+] 隧道已打通：SSH 登录自检通过"
elif grep -Eiq 'Permission denied \((publickey|keyboard-interactive|publickey,password)|No more authentication methods to try' "$TUNNEL_TEST_ERR"; then
    if [ -n "${FPRO_TUNNEL_SSH_KEY:-}" ] || [ "${FPRO_TUNNEL_REQUIRE_SSH:-0}" = "1" ]; then
        echo "[-] 隧道已响应，但 SSH 私钥认证失败。" >&2
        exit 1
    fi
    echo "[!] 隧道端口已响应，但容器内没有可用 SSH 私钥；已跳过登录验证。"
else
    echo "[-] 隧道回环自检未通过（连接或 SSH 握手失败），请稍后重试：" >&2
    echo "      ssh -p $TUNNEL_PORT root@$TUNNEL_HOST" >&2
    exit 1
fi

echo "=========================================================="
echo "  部署完成。"
echo "  本机连接命令： ssh -p $TUNNEL_PORT root@$TUNNEL_HOST"
echo "=========================================================="
