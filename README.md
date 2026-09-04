# fpro 重装部署方案（Cloud Studio 容器）

## 作用

Cloud Studio 容器重启后，容器内的 `fpro-client`、`sshd` 和隧道进程可能消失。本方案提供一个加密的配置载荷，以及按平台分别加密的 fpro 客户端/服务端二进制文件。重启后只需取得脚本、对应文件和解压密码即可恢复服务。

实际服务端地址、端口、CA 标识和认证材料只保存在加密载荷或运行时配置中，不在本说明中公开。

> 操作者按步骤执行的速查版见 [使用说明.md](使用说明.md)。

## Windows 操作者：使用 EXE 启动临时通道

构建后生成 `dist/FProCloudStudio.exe`。Windows 操作者通常只需双击该文件，
输入一次“密钥传输密码”并点击“启动临时通道”；这是唯一必填项。程序会按本机架构下载加密客户端、
解密配置并启动本机一次性 fpro 通道和文件接收器。配置准备完成后，窗口中的 **复制 bash 命令**
按钮会立即变为可用（无需等到后台健康检查结束）；通道就绪后命令还会自动复制一次。
操作者直接粘贴到 Cloud Studio 容器终端即可；程序不会控制浏览器、CDP 或终端。
临时接收通道默认在真正就绪后保持 60 分钟，成功收到加密密钥包或点击“停止”才会立即关闭；
可在高级设置中调整保持时间（最长 24 小时）。
安装脚本完成后，程序接收并解密 SSH 私钥到 `%USERPROFILE%\.ssh`。通常无需填写端口或服务器地址，也无需手动填写文件接收 token。

EXE 内置解密和密钥校验逻辑，不要求另外安装 Python 或 OpenSSL；网络访问和
Cloud Studio 登录仍须由操作者提供。构建命令及高级/手动流程见
[使用说明.md](使用说明.md)。

## 功能边界（核对）

本方案的临时 fpro 通道用于一次性传输**加密的 SSH 私钥包**，不是通用文件
同步服务。GUI 会让目标容器生成 Ed25519 密钥，把公钥写入
`/root/.ssh/authorized_keys`（关闭 SSH 密码登录），再将私钥和公钥打成加密
包，经临时通道发送回本机；本机接收器校验、解密并写入
`%USERPROFILE%\.ssh\fpro-cloudstudio`。配置包和按架构选择的 fpro 二进制则通过
HTTPS 下载，mTLS 证书、客户端私钥和 auth token 只作为临时 fpro 通道的内部材料。

## 文件布局

仓库根目录中的二进制文件保持平台原名，仅在末尾增加 `.enc`：

```text
fpro-deploy.tar.gz.enc                 配置、证书、sshd 和看门狗载荷
fpro-client_<platform>.<format>.enc    每个平台独立的客户端加密文件
fpro-server_<platform>.<format>.enc    每个平台独立的服务端加密文件
install.sh                             容器侧安装脚本
```

例如，源文件 `fpro-client_linux_amd64.b64` 会单独加密为
`fpro-client_linux_amd64.b64.enc`；不会把所有平台合并成一个二进制包。`.b64`
文件解密后由安装脚本自动解码，Windows `.exe` 文件则保持原始格式。

`payload/` 是本机审计用的明文目录，已被 Git 忽略，不应提交。

## 安装

在目标 Linux 容器中执行：

```bash
sudo bash install.sh
```

仓库允许匿名读取时，也可以直接从 GitHub Raw 执行；脚本会自动下载配置包和当前架构的客户端：

```bash
curl -fsSL https://raw.githubusercontent.com/bot0577/fpro-cloudstudio-deploy/main/install.sh | sudo bash
```

仓库公开后，Raw 请求无需 GitHub 登录即可读取脚本和加密载荷。若部署在私有镜像中，Raw 请求需要读取权限；此时推荐先使用 Git 凭据做稀疏克隆，或在运行环境中以环境变量提供只读的 `FPRO_GITHUB_TOKEN`。不要把令牌写进 URL、脚本或 Git 历史。

如使用镜像或固定版本，可用 `FPRO_REPO_RAW_BASE_URL` 指定不含文件名的 HTTPS Raw 目录。

脚本会读取 `uname -s` 和 `uname -m`，选择对应的 Linux 客户端文件，例如
`x86_64` 使用 `fpro-client_linux_amd64.b64.enc`，`aarch64` 使用
`fpro-client_linux_arm64.b64.enc`。本地包和二进制存在时使用脚本同目录文件，否则自动使用默认 GitHub Raw 目录。

安装末尾会进行隧道端口自检：脚本探测加密配置中的远端端口，端口能建立
TCP 连接即判定映射已响应。若要再做完整 SSH 登录验证，可设置
`FPRO_TUNNEL_SSH_KEY=/path/to/key`；自动化环境也可设置
`FPRO_TUNNEL_REQUIRE_SSH=1`，要求必须提供该私钥并通过登录验证。完全没有
私钥时使用 `FPRO_SSH_GENERATE=1`，脚本会生成并导出一份加密的登录密钥，
详见下方“SSH 登录密钥”。

脚本可重复执行：重跑时会等待旧看门狗释放锁，再启动新实例。

也可以从 HTTPS 地址取配置包。若二进制文件位于同一远程目录，脚本会自动推导地址：

```bash
sudo env PKG_URL="https://<host>/<path>/fpro-deploy.tar.gz.enc" bash install.sh
```

如果二进制文件位于另一目录，可显式指定：

```bash
sudo env \
  PKG_URL="https://<host>/<config-path>/fpro-deploy.tar.gz.enc" \
  BINARY_BASE_URL="https://<host>/<binary-path>" \
  bash install.sh
```

特殊平台可以用 `FPRO_BINARY_NAME` 手动指定加密文件对应的原始文件名；脚本仍会在解密后校验并安装该文件。

安装脚本兼容两种配置包结构：解包后直接出现 `certs/`、`ssh/` 等目录，或这些目录位于 `payload/` 子目录中。旧版仍携带 amd64 二进制时会兼容使用，但新包默认从独立加密文件获取二进制。

### 只拉取当前架构文件

仓库较大时可以使用 Git 部分克隆和稀疏检出，只下载当前 Linux 架构所需的客户端：

```bash
case "$(uname -m)" in
  x86_64|amd64) name=fpro-client_linux_amd64.b64 ;;
  aarch64|arm64) name=fpro-client_linux_arm64.b64 ;;
  armv7*|armhf|arm) name=fpro-client_linux_arm_armv7.b64 ;;
  armv5*|armv6*|arm5*) name=fpro-client_linux_arm_armv5.b64 ;;
  loongarch64) name=fpro-client_linux_loong64.b64 ;;
  riscv64) name=fpro-client_linux_riscv64.b64 ;;
  mips64el|mips64le) name=fpro-client_linux_mips64le.b64 ;;
  mips64) name=fpro-client_linux_mips64.b64 ;;
  mipsel) name=fpro-client_linux_mipsle_softfloat.b64 ;;
  mips) name=fpro-client_linux_mips_softfloat.b64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
git clone --filter=blob:none --no-checkout \
  https://github.com/bot0577/fpro-cloudstudio-deploy.git fpro-deploy
cd fpro-deploy
git sparse-checkout init --cone
git sparse-checkout set install.sh README.md fpro-deploy.tar.gz.enc "$name.enc"
git checkout
sudo bash install.sh
```

私有仓库的 Git 凭据由 Git 自身处理；不要把令牌写入 URL、脚本或配置文件。

## 配置载荷

配置载荷包含：

```text
certs/ca.crt                   服务端 CA（仅在加密载荷内）
certs/client.crt              客户端证书
certs/client.key              客户端私钥
certs/auth-token              加密载荷内的 token 参考副本
fpro-client.toml              客户端运行配置
sshd_config.d/90-ragp.conf    root 密钥登录配置
ssh/authorized_keys           本机公钥
watchdog.sh                   看门狗
manifest.json                 元数据
```

服务端地址、认证 token 和证书身份由加密配置使用；README 不重复这些值。

## SSH 登录密钥

这里有两类完全不同的“私钥”：`certs/client.key` 是 fpro 客户端连接服务端
用的 mTLS 私钥；SSH 登录 root 使用的是 `ssh/authorized_keys` 对应的另一对
密钥。端口探测只能证明 TCP 映射有响应，不能替代 SSH 公钥认证。

默认载荷只放 SSH **公钥**，不会凭空给操作者生成一个可找回的私钥。安装脚本
会输出公钥指纹；你必须在本机保留与该指纹匹配的私钥，然后这样连接：

```bash
ssh -i ~/.ssh/fpro-cloudstudio -p <remote-port> root@<tunnel-host>
```

### 本机已有密钥

把本机公钥作为 `FPRO_AUTHORIZED_KEYS_FILE` 传给安装脚本；如果同时提供私钥，
脚本会先校验公钥/私钥指纹是否一致，再启动 sshd：

```bash
sudo env \
  FPRO_AUTHORIZED_KEYS_FILE=/path/to/id_ed25519.pub \
  FPRO_SSH_PRIVATE_KEY=/path/to/id_ed25519 \
  FPRO_TUNNEL_SSH_KEY=/path/to/id_ed25519 \
  bash install.sh
```

`FPRO_AUTHORIZED_KEYS_FILE` 指向的是**目标容器内**可读的文件；若密钥只在
Windows/macOS 本机，先通过 Cloud Studio 文件上传或本地 provisioning 工具
把 `.pub` 传入容器，再运行安装脚本。

私钥只在操作者自己的电脑上使用，不会通过 Git、GitHub Raw 或 bridge 上传。

### 完全没有密钥时

在目标容器中显式启用一次性生成模式。脚本会生成 Ed25519 密钥，只把公钥加入
`authorized_keys`，并用本次解压密码把私钥和公钥打成一个单独的加密导出文件：

```bash
sudo env FPRO_SSH_GENERATE=1 bash install.sh
```

默认导出文件为当前目录下的
`fpro-cloudstudio-SHA256_<fingerprint>.tar.gz.enc`（当前目录不可写时落到
`/tmp`）；也可以指定一个明确位置：

```bash
sudo env \
  FPRO_SSH_GENERATE=1 \
  FPRO_SSH_EXPORT_PATH=/workspace/fpro-cloudstudio-key.tar.gz.enc \
  bash install.sh
```

把这个 `.enc` 文件下载到本机后，用**同一个解压密码**解开（不要把密码写进
命令行或 Git 历史）：

```bash
mkdir -p ~/.ssh
openssl enc -d -aes-256-cbc -pbkdf2 \
  -in fpro-cloudstudio-key.tar.gz.enc -pass stdin \
  | tar -xzf - -C ~/.ssh
chmod 600 ~/.ssh/fpro-cloudstudio
ssh -i ~/.ssh/fpro-cloudstudio -p <remote-port> root@<tunnel-host>
```

如果安装是直接以 root 登录容器、导出文件因此属于 root，可先在容器终端执行
`sudo cp /path/to/fpro-cloudstudio-key.tar.gz.enc /workspace/`，再从工作区下载；
不要把解密后的私钥放回共享工作区。

导出文件只用于完成一次密钥交付；解密后应从共享工作区删除。若解压密码已经
泄露，应立即重新生成一对密钥并重新部署公钥。也可以用
`FPRO_SSH_EXPORT_PASSWORD` 为导出文件设置不同的密码（通过安全的环境注入，
不要写入脚本）。

若只是想在已有私钥的情况下生成一个加密备份，可设置
`FPRO_SSH_EXPORT=1 FPRO_SSH_PRIVATE_KEY=/path/to/key`；脚本仍会先检查公钥
指纹，且不会打印私钥内容。

无论采用哪种方式，安装末尾的端口自检仍以 TCP 端口存活为默认成功标准；只有
显式提供 `FPRO_TUNNEL_SSH_KEY` 或设置 `FPRO_TUNNEL_REQUIRE_SSH=1`，才会追加真实 SSH 登录验证。

### 通过一次性 fpro 通道接收（EXE 推荐）

Windows 直接运行 EXE 即可完成下面的接收器和临时代理启动；不需要手动启动
`tools/fpro_ssh_receiver.py`。EXE 会在本机回环地址启动一次性 HTTP 接收器，
再用临时的 fpro TCP 代理把一个未占用的远端端口转回该接收器。加密包抵达后，
接收器在本机校验密码 challenge-response、SHA-256、SSH 指纹以及私钥/公钥匹配关系，
再解密安装私钥；解压密码本身从不通过网络发送。

Cloud Studio 的命令必须由操作者手动粘贴并执行。命令通过 HTTPS 获取 `install.sh`，
脚本只以 ASCII 提示 `FPRO package password`，要求输入与 EXE 中相同的密钥传输密码；不再需要复制、粘贴或手工填写文件接收 token。密码与接收器 challenge、密钥包 SHA-256 和 SSH 指纹组合后计算一次性 HMAC proof，
因此密码不会出现在命令行、剪贴板或 shell history 中。EXE 的“复制 bash 命令”按钮可随时再次复制。该临时通道只负责传回加密 SSH 密钥包，不承载后续 SSH 会话；接收完成后通道会立即关闭，
容器内的持久 fpro/SSH 映射由看门狗继续维持。为避免 Cloud Studio 冷启动、下载或安装耗时造成中断，
默认超时是通道就绪后的 60 分钟（高级设置可调整，最长 24 小时）。

手动使用 CLI 接收器时，只需准备配置包密码和 mTLS 文件（这些文件不得提交到 Git）：

```text
<fpro-auth-token-file>      fpro 服务端认证 token（从加密载荷取出）
<package-password-file>     fpro-deploy.tar.gz.enc 的密码
<client.crt> <client.key> <ca.crt>    临时 fpro 客户端的 TLS 材料
```

然后在仓库根目录启动代理；`<unused-remote-port>` 必须是服务端允许且当前未被
占用的端口：

```bash
python tools/fpro_ssh_receiver.py proxy \
  --fpro-binary <path-to-fpro-client> \
  --server-addr <fpro-server-host> \
  --server-port <fpro-control-port> \
  --remote-port <unused-remote-port> \
  --tls-cert <path-to-client.crt> \
  --tls-key <path-to-client.key> \
  --tls-ca <path-to-ca.crt> \
  --tls-server-name <tls-server-name> \
  --fpro-token-file <fpro-auth-token-file> \
  --password-file <package-password-file> \
  --password-auth \
  --ssh-dir ~/.ssh \
  --key-name fpro-cloudstudio
```

`--password-auth` 让接收器使用配置包密码的 challenge-response；`--fpro-token-file`
仍是 fpro 客户端连接服务端所需的内部认证 token，只从本机受保护的解密载荷读取，
不会传给 Cloud Studio。工具会先请求 `/healthz` 确认完整 HTTP 路径可用，不使用会占用
首个 work connection 的裸 TCP 探测。启动后只需把 URL 交给容器安装脚本：

```bash
sudo env \
  FPRO_SSH_GENERATE=1 \
  FPRO_SSH_RECEIVER_URL="http://<fpro-server-host>:<unused-remote-port>/v1/ssh-key" \
  FPRO_SSH_RECEIVER_AUTH=password \
  bash install.sh
```

容器端输入的配置包密码必须与本机 `--password-file` 内容相同。password-auth
模式下 SSH 导出包也强制使用这个密码，从而整个流程只需一个密码。旧版 CLI 如需
兼容，仍可显式设置 `FPRO_SSH_RECEIVER_TOKEN(_FILE)` 使用传统 token 模式；EXE
默认不会生成、显示或要求该 token。
password-auth 自动交付需要容器提供 `python3`；缺少时脚本会明确报错，不会把密码
降级放到命令行参数中。
安装脚本会把
临时生成的 SSH 私钥打成单独的加密包并 POST 到上述端点；本机接收器收到并验证
后自动解密写入 `--ssh-dir`，随后临时 fpro 客户端自动退出。成功时无需下载文件；
失败时安装脚本不会报告部署完成，并尽量保留加密包供排障。`--response-grace`
可按网络状况调整（默认 3 秒），不需要长期开放接收端口。

本地接收器也可单独处理已经取得的包：

```bash
python tools/fpro_ssh_receiver.py decrypt \
  --input fpro-cloudstudio-key.tar.gz.enc \
  --password-file <package-password-file> \
  --ssh-dir ~/.ssh
```

接收器默认只绑定 `127.0.0.1`，使用短时 challenge-response proof、必需的
SHA-256 与 SSH 指纹头、大小限制、路径穿越/软链接检查、私钥与 `.pub` 匹配检查
以及原子写入。只有明确指定 `--allow-public` 才会允许监听非回环地址；即使如此，
仍应依赖 fpro TLS 和加密包密码共同保护传输。

## 安全约定

- 每个二进制文件单独使用 AES-256-CBC + PBKDF2 加密，文件名保留平台信息。
- Git 只提交脚本、文档和 `.enc` 文件；明文 `payload/`、私钥、auth token 与 bridge 配置不得明文提交。
- `FPRO_SSH_GENERATE=1` 生成的私钥只会短暂存在于容器临时目录，随后写入
  密码保护的 `.tar.gz.enc`；解密后的私钥应立即移到本机并删除导出文件。
- 本地 bridge 配置只供本机连接使用，不属于部署载荷，也不上传到仓库。
- 仓库可以公开：真实服务地址、证书身份、客户端私钥、auth token 和 bridge 配置只允许存在于加密载荷或运行时安全存储中。解密密码不写入命令行、脚本或 Git 历史。
- 解密后的临时文件由安装脚本在退出时清理；运行中的配置文件仍应按主机权限保护。

## 重新加密单个平台文件

每个平台单独执行一次，不要把多个二进制合并：

```bash
name="fpro-client_linux_amd64.b64"
printf '%s\n' "$PASS" | openssl enc -aes-256-cbc -pbkdf2 \
  -in "$name" -out "$name.enc" -pass stdin
```

服务端文件使用同样方式，只替换 `name`。配置载荷则单独打包为
`fpro-deploy.tar.gz.enc`，不要把平台二进制再次放进其中。
