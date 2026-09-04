#!/usr/bin/env bash
# ============================================================================
#  fpro 容器安装脚本 (Cloud Studio 容器侧)
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
#    # 没有本地 SSH 密钥时，生成一对并导出加密私钥包：
#    sudo env FPRO_SSH_GENERATE=1 bash install.sh
#    # 使用本机 fpro_ssh_receiver.py 建立的一次性接收端点自动交付：
#    sudo env FPRO_SSH_GENERATE=1 FPRO_SSH_RECEIVER_URL=... \
#      FPRO_SSH_RECEIVER_TOKEN_FILE=/path/to/token bash install.sh
#    # 自动化调用方也可把密码放入临时 600 文件，完成后立即删除：
#    sudo env FPRO_PACKAGE_PASSWORD_FILE=/path/to/password bash install.sh
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
SSH_KEY_NAME="${FPRO_SSH_KEY_NAME:-fpro-cloudstudio}"
SSH_RECEIVER_URL="${FPRO_SSH_RECEIVER_URL:-}"
SSH_RECEIVER_TOKEN="${FPRO_SSH_RECEIVER_TOKEN:-}"
SSH_RECEIVER_TOKEN_FILE="${FPRO_SSH_RECEIVER_TOKEN_FILE:-}"
SSH_RECEIVER_TIMEOUT="${FPRO_SSH_RECEIVER_TIMEOUT:-60}"
PACKAGE_PASSWORD_FILE="${FPRO_PACKAGE_PASSWORD_FILE:-}"
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

[[ "$SSH_KEY_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || die "FPRO_SSH_KEY_NAME 只能包含字母、数字、点、下划线和连字符。"
[[ "$RAW_BASE_URL" == https://* ]] || die "FPRO_REPO_RAW_BASE_URL 必须使用 HTTPS。"
if [ -n "$SSH_RECEIVER_URL" ]; then
    [[ "$SSH_RECEIVER_URL" =~ ^https?://[^[:space:]]+$ ]] \
        || die "FPRO_SSH_RECEIVER_URL 必须是 http(s) URL。"
    if [ -n "$SSH_RECEIVER_TOKEN_FILE" ]; then
        [ -z "$SSH_RECEIVER_TOKEN" ] \
            || die "请只设置 FPRO_SSH_RECEIVER_TOKEN 或 FPRO_SSH_RECEIVER_TOKEN_FILE 其中一个。"
        [ -f "$SSH_RECEIVER_TOKEN_FILE" ] \
            || die "FPRO_SSH_RECEIVER_TOKEN_FILE 不存在：$SSH_RECEIVER_TOKEN_FILE"
        # Read exactly the first line; the token itself never enters the
        # command line or shell history.  A missing final newline is valid.
        IFS= read -r SSH_RECEIVER_TOKEN < "$SSH_RECEIVER_TOKEN_FILE" || true
        SSH_RECEIVER_TOKEN="${SSH_RECEIVER_TOKEN%$'\r'}"
    fi
    [[ "$SSH_RECEIVER_TOKEN" =~ ^[A-Za-z0-9._~-]{16,256}$ ]] \
        || die "FPRO_SSH_RECEIVER_TOKEN 必须是 16-256 位随机 token。"
    [[ "$SSH_RECEIVER_TIMEOUT" =~ ^[1-9][0-9]*$ ]] \
        || die "FPRO_SSH_RECEIVER_TIMEOUT 必须是正整数秒数。"
elif [ -n "$SSH_RECEIVER_TOKEN" ] || [ -n "$SSH_RECEIVER_TOKEN_FILE" ]; then
    die "设置 FPRO_SSH_RECEIVER_TOKEN(_FILE) 前必须先设置 FPRO_SSH_RECEIVER_URL。"
fi

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

# Return the remote port belonging to the SSH proxy (container port 22).
# fpro-client.toml may contain more than one [[proxies]] block, so reading the
# first remotePort is unsafe: it could be a different application service.
# Prefer the explicitly named cloudstudio-ssh block, then any block whose
# localPort is 22.  The caller can still fall back to the legacy single-proxy
# layout when older encrypted payloads do not include localPort metadata.
read_ssh_proxy_remote_port() {
    local file="$1" line key value
    local in_proxy=0 name="" local_port="" remote_port="" first_remote=""

    finish_proxy() {
        if [ "$in_proxy" -eq 1 ] && [ "$local_port" = "22" ] \
                && [[ "$remote_port" =~ ^[0-9]+$ ]]; then
            if [ "$name" = "cloudstudio-ssh" ]; then
                printf '%s\n' "$remote_port"
                return 0
            fi
            [ -n "$first_remote" ] || first_remote="$remote_port"
        fi
        return 1
    }

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -n "$line" ] || continue

        if [ "$line" = "[[proxies]]" ]; then
            if finish_proxy; then
                return 0
            fi
            in_proxy=1
            name=""
            local_port=""
            remote_port=""
            continue
        fi
        # A different TOML table ends the current proxy block.
        if [[ "$line" == \[*\] && "$line" != "[[proxies]]" ]]; then
            if finish_proxy; then
                return 0
            fi
            in_proxy=0
            continue
        fi
        [ "$in_proxy" -eq 1 ] || continue
        if [[ "$line" =~ ^([A-Za-z0-9_.-]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            if [[ "$value" == \"*\" && "$value" == *\" ]]; then
                value="${value:1:${#value}-2}"
            elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
                value="${value:1:${#value}-2}"
            fi
            case "$key" in
                name) name="$value" ;;
                localPort) local_port="$value" ;;
                remotePort) remote_port="$value" ;;
            esac
        fi
    done < "$file"

    if finish_proxy; then
        return 0
    fi
    if [ -n "$first_remote" ]; then
        printf '%s\n' "$first_remote"
        return 0
    fi
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
echo "  fpro 容器安装 — 请输入配置包解密密码"
echo "=========================================================="
if [ -n "$PACKAGE_PASSWORD_FILE" ]; then
    [ -f "$PACKAGE_PASSWORD_FILE" ] || die "FPRO_PACKAGE_PASSWORD_FILE 不存在：$PACKAGE_PASSWORD_FILE"
    # Read one line so a Windows-style final newline cannot accidentally
    # become part of the password used for the SSH export bundle.
    IFS= read -r PASS < "$PACKAGE_PASSWORD_FILE" || true
    PASS="${PASS%$'\r'}"
elif [ -t 0 ]; then
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

# PASS 还要用于可选的 SSH 私钥加密导出；完成导出后立即清除。
SSH_PUBLIC_KEY_SOURCE=""
SSH_DERIVED_PUBLIC_KEY=""
SSH_PRIVATE_KEY_PATH=""
SSH_KEY_FINGERPRINT=""
SSH_KEY_EXPORT_PATH=""
SSH_KEY_GENERATED=0
SSH_GENERATED_KEY_PASSPHRASE=""
SSH_KEY_DELIVERED=0

# ---- 3. 清理旧实例（先看门狗、后客户端，避免锁被子进程继承） -----------
# 看门狗把 flock 文件描述符继承给 fpro-client；必须先停止看门狗，再
# 等待旧客户端完全退出，否则新看门狗可能因旧锁仍被占用而立即结束。
WATCHDOG_PATTERN='/opt/fpro-client/watchdog.sh'
list_watchdog_pids() {
    local proc pid cmdline
    for proc in /proc/[0-9]*; do
        [ -r "$proc/cmdline" ] || continue
        pid="${proc##*/}"
        [ "$pid" = "$$" ] && continue
        cmdline="$(tr '\0' '\n' < "$proc/cmdline" 2>/dev/null || true)"
        # 使用 here-string 避免 pipefail + grep -q 的 SIGPIPE 误判。
        if grep -Fx "$WATCHDOG_PATTERN" <<< "$cmdline" >/dev/null 2>&1; then
            printf '%s\n' "$pid"
        fi
    done
}

old_watchdogs="$(list_watchdog_pids)"
if [ -n "$old_watchdogs" ]; then
    while IFS= read -r pid; do
        [ -n "$pid" ] && [ "$pid" != "$$" ] && kill "$pid" 2>/dev/null || true
    done <<< "$old_watchdogs"
    for ((i = 0; i < 40; i++)); do
        [ -z "$(list_watchdog_pids)" ] && break
        sleep 0.25
    done
    # 极端情况下旧实例卡住时才强制结束；正常路径不会走到这里。
    while IFS= read -r pid; do
        [ -n "$pid" ] && [ "$pid" != "$$" ] && kill -KILL "$pid" 2>/dev/null || true
    done < <(list_watchdog_pids)
fi

echo "[*] 清理既有 fpro-client 进程 ..."
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    case "$exe" in
        */fpro-client) kill "$pid" 2>/dev/null && echo "    终止旧进程 pid=$pid" ;;
    esac
done
# 兜底：用进程名精确匹配再清一次，然后等待其释放继承的 flock。
pkill -x fpro-client 2>/dev/null || true
for ((i = 0; i < 40; i++)); do
    pgrep -x fpro-client >/dev/null 2>&1 || break
    sleep 0.25
done
# 极端情况下旧客户端卡住时才强制结束；正常路径不会走到这里。
pkill -KILL -x fpro-client 2>/dev/null || true

# 旧版看门狗可能把锁描述符遗留给 sleep/fpro-client 子进程；逐个检查
# 描述符并清理专属锁的持有者，确保新实例不会因旧锁竞态而退出。
WATCHDOG_LOCK='/var/lock/fpro-client-watchdog.lock'
WATCHDOG_LOCK_REAL="$(readlink -f "$WATCHDOG_LOCK" 2>/dev/null || printf '%s' "$WATCHDOG_LOCK")"
list_watchdog_lock_holders() {
    local proc fd target pid
    for proc in /proc/[0-9]*; do
        [ -d "$proc/fd" ] || continue
        pid="${proc##*/}"
        [ "$pid" = "$$" ] && continue
        for fd in "$proc"/fd/*; do
            [ -e "$fd" ] || continue
            target="$(readlink "$fd" 2>/dev/null || true)"
            if [ "$target" = "$WATCHDOG_LOCK" ] || [ "$target" = "$WATCHDOG_LOCK_REAL" ]; then
                printf '%s\n' "$pid"
                break
            fi
        done
    done
}

lock_holders="$(list_watchdog_lock_holders)"
if [ -n "$lock_holders" ]; then
    while IFS= read -r pid; do
        [ -n "$pid" ] && [ "$pid" != "$$" ] && kill "$pid" 2>/dev/null || true
    done <<< "$lock_holders"
    for ((i = 0; i < 40; i++)); do
        [ -z "$(list_watchdog_lock_holders)" ] && break
        sleep 0.25
    done
    while IFS= read -r pid; do
        [ -n "$pid" ] && [ "$pid" != "$$" ] && kill -KILL "$pid" 2>/dev/null || true
    done < <(list_watchdog_lock_holders)
fi

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

# 确保 sshd 和 ssh-keygen 存在；容器通常已经预装 openssh-server。
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
    echo "    [!] 未找到 sshd，尝试 apt-get 安装 ..."
    apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq openssh-server openssh-client >/dev/null 2>&1 \
        || echo "    [!] 自动安装失败，请手动安装 openssh-server 后重跑本脚本。"
fi
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
if [ ! -x "$SSHD_BIN" ]; then
    echo "[-] 找不到可执行的 sshd。" >&2
    exit 1
fi
if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "[-] 找不到 ssh-keygen；无法校验或生成 root 登录密钥。" >&2
    exit 1
fi

mkdir -p /root/.ssh && chmod 700 /root/.ssh

key_fingerprint_from_file() {
    local source="$1"
    ssh-keygen -lf "$source" 2>/dev/null | awk 'NF >= 2 { print $2; exit }'
}

validate_authorized_keys() {
    local source="$1" line found=0
    [ -s "$source" ] || die "找不到有效的 SSH 公钥文件：$source"
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        case "$line" in
            ""|\#*) continue ;;
        esac
        if ! printf '%s\n' "$line" | ssh-keygen -lf - >/dev/null 2>&1; then
            die "SSH 公钥格式无效：$source"
        fi
        found=1
    done < "$source"
    [ "$found" -eq 1 ] || die "SSH 公钥文件为空：$source"
}

derive_public_key() {
    local private="$1" output="$2"
    if ! ssh-keygen -y -f "$private" > "$output" 2>/dev/null; then
        die "无法从 SSH 私钥读取公钥：$private（若私钥有口令，请先使用无口令副本或跳过自动自检）"
    fi
    [ -s "$output" ] || die "从 SSH 私钥导出的公钥为空：$private"
}

# 密钥来源优先级：显式公钥 → 显式私钥导出的公钥 → 自动生成 →
# 加密载荷中可选的私钥 → 加密载荷中的公钥。默认只落地公钥，私钥不会
# 被脚本打印或写入 Git；FPRO_SSH_GENERATE=1 才会生成一次性密钥并导出。
SSH_EXPLICIT_PUBLIC="${FPRO_AUTHORIZED_KEYS_FILE:-}"
SSH_INLINE_PUBLIC="${FPRO_AUTHORIZED_KEY:-}"
SSH_EXPLICIT_PRIVATE="${FPRO_SSH_PRIVATE_KEY:-}"
PAYLOAD_PRIVATE_KEY="$PAY/ssh/$SSH_KEY_NAME"

if [ -n "$SSH_EXPLICIT_PRIVATE" ]; then
    [ -f "$SSH_EXPLICIT_PRIVATE" ] || die "FPRO_SSH_PRIVATE_KEY 不存在：$SSH_EXPLICIT_PRIVATE"
    SSH_DERIVED_PUBLIC_KEY="$TMP/authorized_keys.from-private"
    derive_public_key "$SSH_EXPLICIT_PRIVATE" "$SSH_DERIVED_PUBLIC_KEY"
    SSH_PRIVATE_KEY_PATH="$SSH_EXPLICIT_PRIVATE"
fi

if [ -n "$SSH_INLINE_PUBLIC" ]; then
    SSH_PUBLIC_KEY_SOURCE="$TMP/authorized_keys.inline"
    printf '%s\n' "$SSH_INLINE_PUBLIC" > "$SSH_PUBLIC_KEY_SOURCE"
elif [ -n "$SSH_EXPLICIT_PUBLIC" ]; then
    SSH_PUBLIC_KEY_SOURCE="$SSH_EXPLICIT_PUBLIC"
elif [ -n "$SSH_EXPLICIT_PRIVATE" ]; then
    SSH_PUBLIC_KEY_SOURCE="$SSH_DERIVED_PUBLIC_KEY"
elif [ "${FPRO_SSH_GENERATE:-0}" = "1" ]; then
    SSH_KEY_DIR="$TMP/generated-ssh"
    mkdir -p "$SSH_KEY_DIR"
    SSH_PRIVATE_KEY_PATH="$SSH_KEY_DIR/$SSH_KEY_NAME"
    SSH_GENERATED_KEY_PASSPHRASE="${FPRO_SSH_KEY_PASSPHRASE:-}"
    if ! ssh-keygen -q -t ed25519 -N "${FPRO_SSH_KEY_PASSPHRASE:-}" \
            -C "$SSH_KEY_NAME" -f "$SSH_PRIVATE_KEY_PATH"; then
        die "SSH 密钥生成失败。"
    fi
    SSH_PUBLIC_KEY_SOURCE="$SSH_PRIVATE_KEY_PATH.pub"
    SSH_KEY_GENERATED=1
elif [ -f "$PAYLOAD_PRIVATE_KEY" ]; then
    SSH_PRIVATE_KEY_PATH="$PAYLOAD_PRIVATE_KEY"
    SSH_DERIVED_PUBLIC_KEY="$TMP/authorized_keys.from-payload-private"
    derive_public_key "$SSH_PRIVATE_KEY_PATH" "$SSH_DERIVED_PUBLIC_KEY"
    SSH_PUBLIC_KEY_SOURCE="$SSH_DERIVED_PUBLIC_KEY"
else
    SSH_PUBLIC_KEY_SOURCE="$PAY/ssh/authorized_keys"
fi

validate_authorized_keys "$SSH_PUBLIC_KEY_SOURCE"
SSH_KEY_FINGERPRINT="$(key_fingerprint_from_file "$SSH_PUBLIC_KEY_SOURCE")"
[ -n "$SSH_KEY_FINGERPRINT" ] || die "无法计算 SSH 公钥指纹：$SSH_PUBLIC_KEY_SOURCE"

# 若同时给了私钥和显式公钥，强制校验二者确实是一对，避免部署成功后
# 才发现 root 无法登录。
if [ -n "$SSH_EXPLICIT_PRIVATE" ] && [ -n "$SSH_EXPLICIT_PUBLIC" -o -n "$SSH_INLINE_PUBLIC" ]; then
    PRIVATE_FINGERPRINT="$(key_fingerprint_from_file "$SSH_DERIVED_PUBLIC_KEY")"
    [ "$PRIVATE_FINGERPRINT" = "$SSH_KEY_FINGERPRINT" ] \
        || die "SSH 公钥与 FPRO_SSH_PRIVATE_KEY 不匹配。"
fi

AUTHORIZED_KEYS_TARGET=/root/.ssh/authorized_keys
touch "$AUTHORIZED_KEYS_TARGET"
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in
        ""|\#*) continue ;;
    esac
    if ! grep -Fqx -- "$line" "$AUTHORIZED_KEYS_TARGET" 2>/dev/null; then
        printf '%s\n' "$line" >> "$AUTHORIZED_KEYS_TARGET"
    fi
done < "$SSH_PUBLIC_KEY_SOURCE"
chown root:root "$AUTHORIZED_KEYS_TARGET"
chmod 600 "$AUTHORIZED_KEYS_TARGET"

export_ssh_key_bundle() {
    local requested="${FPRO_SSH_EXPORT:-0}" export_pass dest dest_dir safe_fp key_tar stage_dir
    [ "$SSH_KEY_GENERATED" = "1" ] && requested="${FPRO_SSH_EXPORT:-1}"
    [ -n "$SSH_RECEIVER_URL" ] && requested="1"
    [ "$requested" = "1" ] || return 0
    [ -n "$SSH_PRIVATE_KEY_PATH" ] || die "请求导出 SSH 私钥，但当前没有可导出的私钥。"

    export_pass="${FPRO_SSH_EXPORT_PASSWORD:-$PASS}"
    [ -n "$export_pass" ] || die "SSH 私钥导出密码为空。"
    safe_fp="${SSH_KEY_FINGERPRINT//:/_}"
    safe_fp="${safe_fp//\//_}"
    dest="${FPRO_SSH_EXPORT_PATH:-}"
    if [ -z "$dest" ]; then
        # Receiver mode keeps the encrypted bundle only in TMP; it is removed
        # after the one-shot transfer and never appears in the shared workspace.
        if [ -n "$SSH_RECEIVER_URL" ]; then
            dest="$TMP/${SSH_KEY_NAME}-${safe_fp}.tar.gz.enc"
        elif [ -d "$DIR" ] && [ -w "$DIR" ]; then
            dest="$DIR/${SSH_KEY_NAME}-${safe_fp}.tar.gz.enc"
        else
            dest="/tmp/${SSH_KEY_NAME}-${safe_fp}.tar.gz.enc"
        fi
    fi
    case "$dest" in
        ""|/|.) die "FPRO_SSH_EXPORT_PATH 不安全或为空。" ;;
    esac
    dest_dir="$(dirname "$dest")"
    mkdir -p "$dest_dir" || die "无法创建 SSH 私钥导出目录：$dest_dir"
    key_tar="$TMP/${SSH_KEY_NAME}.tar.gz"
    stage_dir="$TMP/ssh-export"
    mkdir -p "$stage_dir"
    cp "$SSH_PRIVATE_KEY_PATH" "$stage_dir/$SSH_KEY_NAME"
    cp "$SSH_PUBLIC_KEY_SOURCE" "$stage_dir/$SSH_KEY_NAME.pub"
    chmod 600 "$stage_dir/$SSH_KEY_NAME"
    chmod 644 "$stage_dir/$SSH_KEY_NAME.pub"
    tar -czf "$key_tar" -C "$stage_dir" "$SSH_KEY_NAME" "$SSH_KEY_NAME.pub"
    printf '%s\n' "$export_pass" | openssl enc -aes-256-cbc -pbkdf2 \
        -in "$key_tar" -out "$dest" -pass stdin 2>/dev/null \
        || die "SSH 私钥加密导出失败：$dest"
    chmod 600 "$dest"
    # sudo 场景下把加密导出文件交给实际操作者，便于从 Cloud Studio
    # 工作区下载；如果无法解析 SUDO_USER，保持 root 所有权并提示手动复制。
    if [ -n "${SUDO_USER:-}" ] && id "$SUDO_USER" >/dev/null 2>&1; then
        chown "$SUDO_USER:$(id -gn "$SUDO_USER")" "$dest" 2>/dev/null || true
    fi
    SSH_KEY_EXPORT_PATH="$dest"
}

sha256_path() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1; exit}'
    else
        openssl dgst -sha256 -r "$path" | awk '{print $1; exit}'
    fi
}

send_ssh_key_bundle() {
    [ -n "$SSH_RECEIVER_URL" ] || return 0
    [ -s "$SSH_KEY_EXPORT_PATH" ] || die "SSH 私钥加密包不存在，无法交付。"
    local digest="$1" response
    echo "[*] 将加密 SSH 私钥包发送到一次性本机接收器 ..."

    # Python avoids putting the transfer token in the process command line.
    # The token is read from the inherited environment and is never printed.
    if command -v python3 >/dev/null 2>&1; then
        if ! FPRO_SSH_RECEIVER_URL="$SSH_RECEIVER_URL" \
            FPRO_SSH_RECEIVER_TOKEN="$SSH_RECEIVER_TOKEN" \
            FPRO_SSH_RECEIVER_TIMEOUT="$SSH_RECEIVER_TIMEOUT" \
            python3 - "$SSH_KEY_EXPORT_PATH" "$digest" "$SSH_KEY_FINGERPRINT" <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

path, digest, fingerprint = sys.argv[1:4]
url = os.environ["FPRO_SSH_RECEIVER_URL"]
token = os.environ["FPRO_SSH_RECEIVER_TOKEN"]
timeout = float(os.environ.get("FPRO_SSH_RECEIVER_TIMEOUT", "60"))
with open(path, "rb") as stream:
    body = stream.read()
request = urllib.request.Request(
    url,
    data=body,
    method="POST",
    headers={
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(body)),
        "X-FPRO-Transfer-Token": token,
        "X-FPRO-SHA256": digest,
        "X-FPRO-Key-Fingerprint": fingerprint,
        "Connection": "close",
    },
)
try:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = response.read(4096).decode("utf-8", "replace")
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"HTTP {response.status}")
        try:
            parsed = json.loads(result)
        except Exception:
            parsed = {}
        if parsed.get("ok") is not True:
            raise RuntimeError("receiver rejected bundle")
except urllib.error.HTTPError as exc:
    raise SystemExit(f"receiver HTTP {exc.code}")
except Exception as exc:
    raise SystemExit(f"receiver request failed: {exc}")
PY
        then
            SSH_KEY_DELIVERED=1
            if [ "${FPRO_SSH_KEEP_EXPORT:-0}" != "1" ]; then
                rm -f -- "$SSH_KEY_EXPORT_PATH"
                SSH_KEY_EXPORT_PATH=""
            fi
            echo "[+] 加密 SSH 私钥包已由本机接收器接收并解密。"
            return 0
        fi
    elif command -v curl >/dev/null 2>&1; then
        # Minimal fallback for images without Python.  The token is still only
        # used for this short-lived process and the payload remains encrypted.
        if curl --fail --silent --show-error --max-time "$SSH_RECEIVER_TIMEOUT" \
            --proto '=http,https' \
            -H "Content-Type: application/octet-stream" \
            -H "X-FPRO-Transfer-Token: $SSH_RECEIVER_TOKEN" \
            -H "X-FPRO-SHA256: $digest" \
            -H "X-FPRO-Key-Fingerprint: $SSH_KEY_FINGERPRINT" \
            --data-binary "@$SSH_KEY_EXPORT_PATH" "$SSH_RECEIVER_URL" \
            >/dev/null; then
            SSH_KEY_DELIVERED=1
            if [ "${FPRO_SSH_KEEP_EXPORT:-0}" != "1" ]; then
                rm -f -- "$SSH_KEY_EXPORT_PATH"
                SSH_KEY_EXPORT_PATH=""
            fi
            echo "[+] 加密 SSH 私钥包已由本机接收器接收。"
            return 0
        fi
    else
        echo "[-] 接收器交付需要 python3 或 curl。" >&2
    fi
    return 1
}

preserve_failed_ssh_export() {
    [ -n "$SSH_KEY_EXPORT_PATH" ] && [ -f "$SSH_KEY_EXPORT_PATH" ] || return 0
    local fallback="${FPRO_SSH_FALLBACK_PATH:-$DIR/${SSH_KEY_NAME}-$(sha256_path "$SSH_PUBLIC_KEY_SOURCE").tar.gz.enc}"
    if [ "$fallback" = "$SSH_KEY_EXPORT_PATH" ]; then
        return 0
    fi
    if cp "$SSH_KEY_EXPORT_PATH" "$fallback" 2>/dev/null; then
        chmod 600 "$fallback" 2>/dev/null || true
        echo "[!] 自动接收失败，已保留加密包（仍需手动取回）: $fallback" >&2
    else
        echo "[!] 自动接收失败，且无法保留加密包；请检查接收器状态后重试。" >&2
    fi
}

export_ssh_key_bundle
unset PASS

mkdir -p /etc/ssh/sshd_config.d
cp "$PAY/sshd_config.d/90-ragp.conf" /etc/ssh/sshd_config.d/90-ragp.conf
chmod 644 /etc/ssh/sshd_config.d/90-ragp.conf

# OpenSSH applies the first value it sees for most options.  A pre-existing
# Cloud Studio drop-in can therefore win over 90-ragp.conf.  Install an early
# managed copy as well, while retaining the documented 90-ragp.conf path for
# compatibility with older images and audits.
cp "$PAY/sshd_config.d/90-ragp.conf" /etc/ssh/sshd_config.d/00-fpro-cloudstudio.conf
chmod 644 /etc/ssh/sshd_config.d/00-fpro-cloudstudio.conf

mkdir -p /run/sshd
if ! "$SSHD_BIN" -t; then
    echo "[-] sshd 配置校验失败，未启动 sshd。" >&2
    exit 1
fi
effective_sshd_config="$($SSHD_BIN -T 2>/dev/null || true)"
if ! grep -Fxq "passwordauthentication no" <<< "$effective_sshd_config"; then
    echo "[-] sshd 生效配置仍允许密码登录，已中止。" >&2
    exit 1
fi
if ! grep -Eq '^permitrootlogin (prohibit-password|without-password)$' <<< "$effective_sshd_config"; then
    echo "[-] sshd 生效配置未允许 root 密钥登录，已中止。" >&2
    exit 1
fi
if ! pgrep -x sshd >/dev/null 2>&1; then
    if "$SSHD_BIN"; then
        echo "[+] sshd 已启动"
    else
        echo "[-] sshd 启动失败，请检查 sshd 配置。" >&2
        exit 1
    fi
else
    # A running daemon does not reread drop-ins until it receives HUP.  Reload
    # the oldest sshd (normally the master) so the new authorized_keys and
    # password policy apply without dropping existing Cloud Studio sessions.
    sshd_master="$(pgrep -xo sshd || true)"
    if [ -n "$sshd_master" ] && kill -HUP "$sshd_master" 2>/dev/null; then
        echo "[+] sshd 已在运行并重新加载配置"
    else
        echo "[-] sshd 已在运行，但无法重新加载配置。" >&2
        exit 1
    fi
fi

echo "[+] root SSH 公钥指纹: $SSH_KEY_FINGERPRINT"
if [ -n "$SSH_KEY_EXPORT_PATH" ]; then
    echo "[+] SSH 私钥已生成并加密导出: $SSH_KEY_EXPORT_PATH"
    echo "    请把该 .enc 文件下载到本地，用同一解压密码解密后再连接。"
elif [ -n "$SSH_PRIVATE_KEY_PATH" ]; then
    echo "[+] 已确认提供了匹配的 SSH 私钥: $SSH_PRIVATE_KEY_PATH"
else
    echo "[!] 当前只安装了 SSH 公钥；端口响应不代表你已经拥有登录私钥。"
    echo "    请使用与上述指纹匹配的本地私钥，或重跑时设置 FPRO_SSH_GENERATE=1。"
fi

# ---- 6. 拉起看门狗 ---------------------------------------------------------
echo "[*] 启动 fpro-client 看门狗 ..."
nohup /opt/fpro-client/watchdog.sh >>/var/log/fpro-watchdog.log 2>&1 &
watchdog_pid=$!
sleep 4
if ! kill -0 "$watchdog_pid" 2>/dev/null; then
    # 兼容极短暂的 bash→后台进程切换：只要已有看门狗实例接管锁，
    # 就视为启动成功；否则才报告失败。
    if [ -n "$(list_watchdog_pids)" ]; then
        echo "[+] 看门狗已由现有实例接管"
    else
        echo "[-] 看门狗启动失败，请查看 /var/log/fpro-watchdog.log" >&2
        exit 1
    fi
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
# 端口优先取 localPort=22 的 SSH proxy，而不是配置中可能存在的其他
# remotePort；这样“端口存活”明确对应容器 SSH 服务。
TUNNEL_HOST="${FPRO_TUNNEL_HOST:-$(read_toml_scalar serverAddr "$PAY/fpro-client.toml" || true)}"
if [ -n "${FPRO_TUNNEL_PORT:-}" ]; then
    TUNNEL_PORT="$FPRO_TUNNEL_PORT"
else
    TUNNEL_PORT="$(read_ssh_proxy_remote_port "$PAY/fpro-client.toml" || true)"
    if [ -z "$TUNNEL_PORT" ]; then
        # Legacy payload fallback: a single top-level remotePort was used by
        # early releases.  Keep it working, but make the assumption visible.
        TUNNEL_PORT="$(read_toml_scalar remotePort "$PAY/fpro-client.toml" || true)"
        [ -n "$TUNNEL_PORT" ] && echo "[!] 未找到 localPort=22 的 proxy，使用旧版 remotePort。" >&2
    fi
fi
[ -n "$TUNNEL_HOST" ] || die "无法从加密配置读取 serverAddr。"
[[ "$TUNNEL_PORT" =~ ^[0-9]+$ ]] || die "无法从加密配置读取有效的 SSH 映射 remotePort。"
(( TUNNEL_PORT >= 1 && TUNNEL_PORT <= 65535 )) || die "SSH 映射 remotePort 超出 1-65535 范围。"
[[ "$TUNNEL_HOST" =~ ^[A-Za-z0-9._:-]+$ ]] || die "加密配置中的 serverAddr 格式无效。"
echo "[*] SSH 映射：容器 22 -> $TUNNEL_HOST:$TUNNEL_PORT"

# 端口探测是默认成功标准：映射未建立时，frps 的远端端口应不会响应。
# 优先使用 nc；没有 nc 时使用 timeout + Bash /dev/tcp；两者都没有时，
# 使用 Bash 子进程和短轮询实现无额外依赖的超时控制。
probe_tunnel_port() {
    local host="$1" port="$2" probe_pid i
    if command -v nc >/dev/null 2>&1; then
        nc -z -w 8 "$host" "$port" >/dev/null 2>&1
        return $?
    fi
    if command -v timeout >/dev/null 2>&1; then
        timeout 8 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$host" "$port" \
            >/dev/null 2>&1
        return $?
    fi
    (exec 3<>"/dev/tcp/$host/$port") >/dev/null 2>&1 &
    probe_pid=$!
    for ((i = 0; i < 32; i++)); do
        if ! kill -0 "$probe_pid" 2>/dev/null; then
            if wait "$probe_pid"; then
                return 0
            else
                return $?
            fi
        fi
        sleep 0.25
    done
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    return 124
}

echo "[*] 检查隧道端口 ..."
if probe_tunnel_port "$TUNNEL_HOST" "$TUNNEL_PORT"; then
    echo "[+] 隧道端口已响应（端口探测通过）"
else
    echo "[-] 隧道端口未响应，请确认 fpro-client 已连接且映射已建立。" >&2
    exit 1
fi

if [ -n "$SSH_RECEIVER_URL" ]; then
    SSH_BUNDLE_DIGEST="$(sha256_path "$SSH_KEY_EXPORT_PATH")"
    if ! send_ssh_key_bundle "$SSH_BUNDLE_DIGEST"; then
        preserve_failed_ssh_export
        die "SSH 私钥自动交付失败；未继续报告部署完成。"
    fi
    # The token is no longer needed after the one-shot POST.  Remove it from
    # the shell environment before the remaining diagnostics run.
    unset SSH_RECEIVER_TOKEN
fi

# 如调用方提供对应的 SSH 私钥，可在端口探测通过后追加完整登录验证。
# FPRO_SSH_GENERATE=1 时使用本次生成的临时私钥自动完成验证；私钥不会
# 打印到终端，且脚本退出时会清理临时明文，只留下加密导出文件（若启用）。
SELFTEST_KEY="${FPRO_TUNNEL_SSH_KEY:-}"
if [ -z "$SELFTEST_KEY" ] && [ "$SSH_KEY_GENERATED" = "1" ] && [ -z "$SSH_GENERATED_KEY_PASSPHRASE" ]; then
    SELFTEST_KEY="$SSH_PRIVATE_KEY_PATH"
fi
if [ -n "${FPRO_TUNNEL_SSH_KEY:-}" ] || \
        { [ "$SSH_KEY_GENERATED" = "1" ] && [ -z "$SSH_GENERATED_KEY_PASSPHRASE" ]; } || \
        [ -n "$SSH_EXPLICIT_PRIVATE" ] || [ "${FPRO_TUNNEL_REQUIRE_SSH:-0}" = "1" ]; then
    [ -n "$SELFTEST_KEY" ] || die "严格 SSH 自检需要设置 FPRO_TUNNEL_SSH_KEY，或启用 FPRO_SSH_GENERATE=1。"
    [ -f "$SELFTEST_KEY" ] || die "SSH 自检私钥不存在：$SELFTEST_KEY"
    if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=6 -o BatchMode=yes \
        -i "$SELFTEST_KEY" -o IdentitiesOnly=yes \
        -p "$TUNNEL_PORT" "root@$TUNNEL_HOST" 'echo TUNNEL_OK' \
        >/dev/null 2>&1; then
        echo "[+] SSH 登录自检通过"
    else
        echo "[-] 隧道端口已响应，但 SSH 私钥认证失败。" >&2
        exit 1
    fi
fi

echo "=========================================================="
echo "  部署完成。"
if [ "$SSH_KEY_DELIVERED" = "1" ]; then
    echo "  SSH 私钥已交付到本机接收器并完成本地解密。"
    echo "  请使用接收器输出的私钥连接。"
elif [ -n "$SSH_KEY_EXPORT_PATH" ]; then
    echo "  请先在本机解密 SSH 私钥包，再连接："
    echo "    ssh -i ~/.ssh/$SSH_KEY_NAME -p $TUNNEL_PORT root@$TUNNEL_HOST"
elif [ -n "$SSH_PRIVATE_KEY_PATH" ]; then
    echo "  本机请使用与指纹 $SSH_KEY_FINGERPRINT 匹配的私钥："
    echo "    ssh -i <private-key> -p $TUNNEL_PORT root@$TUNNEL_HOST"
else
    echo "  本机请使用与指纹 $SSH_KEY_FINGERPRINT 匹配的私钥："
    echo "    ssh -i <private-key> -p $TUNNEL_PORT root@$TUNNEL_HOST"
fi
echo "=========================================================="
