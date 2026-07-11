# udpfile

`udpfile` 是一个用 Go 编写的加密 UDP 目录传输工具。客户端向服务器提交共享根目录下的相对路径，服务器将该目录内容打包为 `tar.gz`，通过可重试的 UDP 分片传输。路径、元数据、错误和文件分片都会经过身份认证与逐包加密。它同时提供命令行客户端和只监听本机的 Web 助手；目标文件服务器始终只需要开放 UDP 端口。

## 快速开始

需要 Go 1.25 或更高版本。

```bash
go build -o bin/udpfile-server ./cmd/udpfile-server
go build -o bin/udpfile-client ./cmd/udpfile-client
go build -o bin/udpfile-web ./cmd/udpfile-web
go build -o bin/udpfile-keygen ./cmd/udpfile-keygen
```

仓库中也包含已交叉编译的静态 Linux x86-64 版本：

```text
dist/linux-amd64/udpfile-server
dist/linux-amd64/udpfile-client
dist/linux-amd64/udpfile-web
dist/linux-amd64/udpfile-keygen
```

在 Linux 上校验后即可运行：

```bash
cd dist/linux-amd64
sha256sum -c SHA256SUMS
./udpfile-server -help
```

## 生成安全配置

首次部署时，在目标服务器运行一次：

```bash
./bin/udpfile-keygen
```

该命令不会覆盖已有文件，并生成：

```text
.env                         # 端口、目录、共享密钥和密钥路径（权限 0600）
keys/server-private.pem      # 3072 位 RSA 私钥（权限 0600）
keys/server-public.pem       # RSA 公钥
```

编辑 `.env` 中的共享目录和目标 IP：

```dotenv
UDPFILE_SERVER_ADDR=0.0.0.0:9000
UDPFILE_ROOT=/srv/share
UDPFILE_WEB_LISTEN=127.0.0.1:8080
UDPFILE_TARGET_IP=192.168.1.20
UDPFILE_TARGET_PORT=9000
UDPFILE_SHARED_SECRET=<自动生成的 32 字节随机密钥>
UDPFILE_RSA_PRIVATE_KEY=keys/server-private.pem
UDPFILE_RSA_PUBLIC_KEY=keys/server-public.pem
```

服务器保留 `.env` 和 RSA 私钥。客户端需要安全复制同一份共享密钥和 `server-public.pem`，但绝不能复制服务器私钥。三个运行命令都会自动加载当前目录的 `.env`；也可以通过 `UDPFILE_ENV=/path/to/config.env` 指定其他配置文件。

真实 `.env` 和 `keys/` 已被 `.gitignore` 排除；仓库中的 `.env.example` 不包含可用秘密。

## 从本地网页下载

假设目标服务器 IP 是 `192.168.1.20`，需要共享 `/srv/share`。目标电脑只需启动 UDP 文件服务器：

```bash
# 目标服务器：只开放 UDP 9000
./bin/udpfile-server
```

在本地电脑启动 Web 助手：

```bash
./bin/udpfile-web
```

然后用本地浏览器打开：

```text
http://127.0.0.1:8080
```

在页面中输入目标服务器 IP、UDP 端口和目录，例如 `photos/2026`，点击“下载目录”。浏览器最终下载 `2026.tar.gz`；跨电脑的请求、分片、重传和文件内容全部走 UDP，本地 HTTP 仅存在于浏览器与 `127.0.0.1` 上的助手之间。

解压下载结果：

```bash
tar -xzf 2026.tar.gz
```

`udpfile-web` 强制只监听 `127.0.0.1`、`::1` 或 `localhost`，并使用页面令牌与 Host 校验阻止其他网页借本机接口发起下载。

## 命令行客户端下载

不使用浏览器时，可以直接运行 UDP 客户端：

```bash
# 目标服务器
./bin/udpfile-server

# 本地客户端
./bin/udpfile-client \
  -path photos/2026 \
  -out ./received-photos
```

`-path` 必须是相对于服务端 `-root` 的目录路径，也可以用 `.` 请求共享根目录本身。`-out` 指定的本地目录必须尚不存在；客户端只会在下载、校验和解包全部成功后创建它，失败不会留下半成品目录。

## 网络要求

目标服务器默认只监听本机；跨电脑访问时，需要像上例一样使用 `-addr 0.0.0.0:9000`，并在目标服务器防火墙开放对应的 UDP 端口。无需开放 TCP 端口，也不需要在目标服务器运行 HTTP 服务。

本地 Web 助手使用 TCP 8080，但仅绑定本机回环地址，不接受局域网连接，也不需要配置防火墙入站规则。

## 可靠性与边界

- 每个 UDP 数据报不超过 1232 字节；加密后的文件数据块为 1120 字节，避免常见网络上的 IP 分片。
- 客户端逐块请求；请求或响应丢失时，只重试当前元数据/数据块，整个传输受 `-timeout` 控制。
- 完成后校验整个压缩归档的 SHA-256，损坏的传输不会被解包。
- 服务端只接受 `-root` 下的相对目录，拒绝 `..` 越界、普通文件、符号链接和设备等特殊文件。
- 默认单次源目录上限为 10 GiB，可用服务端 `-max-bytes` 调整；客户端另有 `-max-archive` 压缩包大小限制。
- 服务端收到客户端的完成确认后立即清理临时压缩包；若客户端中途断开，则在 `-session-ttl` 到期后清理。

## 加密协议

- 客户端用 32 字节预共享密钥的 HMAC-SHA256 证明访问权限。
- 每次会话生成临时 X25519 ECDH 密钥，实现前向保密。
- 服务端使用 RSA-PSS/SHA-256 签名握手，客户端固定 RSA 公钥以验证服务器身份。
- ECDH 结果通过 HKDF-SHA256 派生独立的客户端→服务端和服务端→客户端密钥。
- 每个方向使用经过认证的递增序列号派生 AES-256-GCM nonce；重复或乱序的旧包会被拒绝，被篡改的数据包会被丢弃并由重试机制以新序列号恢复。
- ARCFour/RC4 不受支持，因为它已不满足现代加密安全要求。

加密不能隐藏通信双方、数据量和时序，也不能阻止 UDP 洪泛等拒绝服务攻击。仍建议用防火墙把 UDP 端口限制为可信客户端 IP；跨公网使用时可再叠加 WireGuard 或 Tailscale。

## 常用参数

```text
udpfile-server:
  -addr          监听地址，默认 127.0.0.1:9000
  -root          共享根目录，默认当前目录
  -max-bytes     单次请求的源文件总大小上限
  -max-sessions  最大并发会话数
  -session-ttl   临时归档保留时间
  -temp-dir      临时归档目录

udpfile-client:
  -server        服务器地址，默认 127.0.0.1:9000
  -path          服务端根目录下的相对目录（必填）
  -out           本地输出目录（必填，必须不存在）
  -timeout       整体传输超时，默认 10m
  -retry         单包重试间隔，默认 300ms
  -max-archive   接受的最大压缩包大小

udpfile-web:
  -listen        本地页面地址，默认 127.0.0.1:8080，只允许回环地址
  -server        页面中预填的目标服务器 IP
  -port          页面中预填的目标 UDP 端口，默认 9000
  -timeout       单次 UDP 下载超时，默认 10m
  -retry         UDP 单包重试间隔，默认 300ms
  -max-archive   浏览器下载的最大压缩包大小
  -max-downloads 最大并发浏览器下载数，默认 2
  -temp-dir      下载过程中使用的临时目录
```

## 测试

```bash
go test ./...
```
