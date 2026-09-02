# fpro 一键重装部署方案（Cloud Studio 容器）

## 作用

Cloud Studio 容器重启后，容器内的 `fpro-client`、`sshd` 和隧道进程可能消失。本方案提供一个加密的配置载荷，以及按平台分别加密的 fpro 客户端/服务端二进制文件。重启后只需取得脚本、对应文件和解压密码即可恢复服务。

实际服务端地址、端口、CA 标识和认证材料只保存在加密载荷或运行时配置中，不在本说明中公开。

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

脚本会读取 `uname -s` 和 `uname -m`，选择对应的 Linux 客户端文件，例如
`x86_64` 使用 `fpro-client_linux_amd64.b64.enc`，`aarch64` 使用
`fpro-client_linux_arm64.b64.enc`。默认情况下，二进制文件与脚本/配置包位于同一目录。

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

## 安全约定

- 每个二进制文件单独使用 AES-256-CBC + PBKDF2 加密，文件名保留平台信息。
- Git 只提交脚本、文档和 `.enc` 文件；明文 `payload/`、私钥、auth token 与 bridge 配置不得明文提交。
- 本地 bridge 配置只供本机连接使用，不属于部署载荷，也不上传到仓库。
- 仓库应保持 **Private**。解密密码不写入命令行、脚本或 Git 历史。
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
