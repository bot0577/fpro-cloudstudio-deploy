# fpro 一键重装部署方案（Cloud Studio 容器）

## 背景
Cloud Studio 容器重启后会丢失运行中的进程（fpro-client / sshd），导致本地经
`[REDACTED_HOST]:7022` 进容器的隧道断掉。本方案把所有需要的东西（二进制、证书、
auth-token、客户端配置、sshd 加固、看门狗）打成**密码加密压缩包**，与一键脚本一起
存到本私有仓库。重启后只需单脚本 + 密码即可重装。

## 架构
```
本地(免密) ──SSH──> [REDACTED_HOST]:7022  (fpro 服务端映射)
                        │  fpro server (bindPort 7000 / quic 7002)
                        │  mTLS(CA [REDACTED_CA]) + AES token
                        ▼
              容器 127.0.0.1:22 (sshd)   ← fpro-client 代理 cloudstudio-ssh
```

- 服务端：[REDACTED_HOST]，控制口 7000/TCP，QUIC 7002，强制 mTLS
- 代理：`cloudstudio-ssh` tcp，容器 22 → 远端 7022（在 allowPorts 7001-7499 内）
- 证书：Cloud Studio 预置客户端证书 `CN=fpro-client`（由 `[REDACTED_CA]` 签发）。
  与 220 上 xray-publisher 的 `fpro-warp-publisher` 身份**相互独立**，复用不会踢掉在跑的 40001/40090 代理。
  **切勿**把 `ca.key` / `frps-server.*` 服务端密钥塞进客户端包（DEPLOYMENT.md 明确要求）。

## 仓库内容
- `install.sh` — 一键部署脚本（明文，提示输密码后解密安装）
- `fpro-deploy.tar.gz.enc` — 加密载荷（AES-256-CBC + PBKDF2）
- `payload/`（仅本地，不入库）— 明文载荷，便于审计

## 载荷内容（解密后）
```
bin/fpro-client_linux_amd64   通用 fpro 客户端 (linux/amd64)
certs/ca.crt                   服务端 CA（客户端校验服务端用）
certs/client.crt              受信客户端证书 (CN=fpro-client)
certs/client.key              客户端私钥（600）
certs/auth-token              AES token 参考副本（实际已内联进 fpro-client.toml）
fpro-client.toml              客户端配置（user=cloudstudio, remotePort 7022）
sshd_config.d/90-ragp.conf    root 密钥登录 / 关密码
ssh/authorized_keys           本机 id_rsa.pub
watchdog.sh                   看门狗（flock 单例，15s 探活）
manifest.json                 元数据
```

## 重装步骤（容器重启后）
1. 取回两个文件（git clone 私有库，或下载 install.sh + .enc）：
   ```bash
   git clone <私有库> fpro-deploy && cd fpro-deploy
   ```
2. 运行（会提示输入解压密码，密码错则中止、不落地任何文件）：
   ```bash
   sudo bash install.sh
   ```
3. 本机验证：
   ```bash
   ssh -p 7022 root@[REDACTED_HOST]
   ```

## 安全说明
- 压缩包 AES-256-CBC + PBKDF2，密码不落盘、不进命令行（走 stdin）。
- `client.key` / `auth-token` 在容器内权限 600。
- 仓库可以公开；切勿把 `payload/` 明文目录提交进库。
- 改密码只需重新 `tar | openssl enc` 生成新的 `.enc` 并替换仓库文件。

## 本地重新打包
```bash
cd payload
tar -czf /tmp/payload.tar.gz .
printf '%s\n' "$PASS" | openssl enc -aes-256-cbc -pbkdf2 \
  -in /tmp/payload.tar.gz -out ../fpro-deploy.tar.gz.enc -pass stdin
```
