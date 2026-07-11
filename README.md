# udpfile

`udpfile` 是一个用 Go 编写的加密 UDP 目录传输工具。客户端向服务器提交共享根目录下的相对路径，服务器将该目录内容打包为 `tar.gz`，通过可重试的 UDP 分片传输。路径、元数据、错误和文件分片都会经过身份认证与逐包加密。它同时提供命令行客户端和只监听本机的 Web 助手；目标文件服务器始终只需要开放 UDP 端口。

## 快速开始

Linux x86-64 机器可直接一键安装：

```bash
curl -fsSL https://raw.githubusercontent.com/zhangga/udpfile/main/install.sh | sh
```

安装器会检查系统和 CPU 架构，下载静态编译产物及 `SHA256SUMS`，校验成功后安装到 `/usr/local/bin/udpfile`。普通用户在需要写入系统目录时会自动调用 `sudo`。

确认安装：

```bash
udpfile help
```

如果没有 root 或 sudo 权限，可以安装到用户目录：

```bash
curl -fsSL https://raw.githubusercontent.com/zhangga/udpfile/main/install.sh \
  | UDPFILE_INSTALL_DIR="$HOME/.local/bin" sh
```

确保 `$HOME/.local/bin` 已加入 `PATH`。内网镜像可设置 `UDPFILE_DOWNLOAD_BASE`。

需要固定标签或提交时，安装器和产物应使用同一个 ref：

```bash
ref='<tag-or-commit>'
curl -fsSL "https://raw.githubusercontent.com/zhangga/udpfile/$ref/install.sh" \
  | UDPFILE_REF="$ref" sh
```

从源码编译需要 Go 1.25 或更高版本：

```bash
go build -o bin/udpfile ./cmd/udpfile
```

仓库中的预编译产物位于：

```text
dist/linux-amd64/udpfile    # Linux x86-64
dist/darwin-arm64/udpfile   # macOS Apple Silicon
```

手动下载时校验后即可运行：

```bash
cd dist/linux-amd64
sha256sum -c SHA256SUMS
chmod +x udpfile
./udpfile help
```

macOS Apple Silicon 手动校验：

```bash
cd dist/darwin-arm64
shasum -a 256 -c SHA256SUMS
chmod +x udpfile
./udpfile help
```

## 零配置启动与首次配对

服务端不再要求预先创建 `.env`、密钥或启动参数。在需要共享的目录中直接运行：

```bash
cd /srv/share
udpfile server
```

默认监听 `0.0.0.0:30033`，共享根目录是启动时的当前目录 `./`。

首次启动会自动生成随机共享密钥和 RSA 身份，默认保存在当前运行用户的系统配置目录：

```text
Linux:  ~/.config/udpfile
macOS:  ~/Library/Application Support/udpfile

server/credentials.json
server/keys/server-private.pem
server/keys/server-public.pem
```

服务器只在首次生成凭据时打印以 `UDF2-` 开头的配对令牌。客户端无需传服务器地址，直接启动本机 Web 页面：

```bash
udpfile client
```

浏览器打开 `http://127.0.0.1:8080` 后，在页面填写服务器 IP、默认端口 `30033`、远端目录和首次配对令牌。传输成功后，客户端会按服务器 `IP:端口` 把凭据保存到上述系统配置目录的 `clients/` 中。后续只需再次运行：

```bash
udpfile client
```

配对令牌包含访问密钥和服务器公钥，等同于访问密码：虽然每台客户端只需输入一次，但令牌本身在服务器换钥前持续有效，不得发到公开聊天或日志。若首次输出没有保存，可运行 `udpfile server -show-pairing-token` 再次显示。

使用 `udpfile download` 进行命令行下载时，程序会通过终端无回显地读取首次令牌。自动化环境可以设置 `UDPFILE_PAIRING_TOKEN`，或通过 `-pair-file /path/to/token` 从权限为 `0600` 的文件读取；`-pair-file -` 表示从标准输入读取。不要把令牌直接写进命令行参数。

配置根目录可通过 `UDPFILE_CONFIG_DIR` 修改。服务端应始终使用同一个系统用户启动；用 `sudo` 启动时凭据会保存在 root 用户的配置目录。

## 可选的显式 `.env` 配置

需要集中管理密钥或兼容旧部署时，仍可手动生成：

```bash
udpfile keygen
```

默认会把 `.env` 和 RSA 密钥写入系统配置目录的 `manual/` 子目录，确保它们不在默认共享根目录 `./` 内。命令结束时会打印实际路径和启动命令。编辑生成的 `.env`：

```dotenv
UDPFILE_SERVER_ADDR=0.0.0.0:30033
UDPFILE_ROOT=.
UDPFILE_WEB_LISTEN=127.0.0.1:8080
UDPFILE_TARGET_IP=192.168.1.20
UDPFILE_TARGET_PORT=30033
UDPFILE_SHARED_SECRET=<自动生成的 32 字节随机密钥>
UDPFILE_RSA_PRIVATE_KEY=<系统配置目录>/manual/keys/server-private.pem
UDPFILE_RSA_PUBLIC_KEY=<系统配置目录>/manual/keys/server-public.pem
```

在共享目录中使用生成的配置启动：

```bash
cd /srv/share
UDPFILE_ENV='<keygen 输出的 .env 路径>' udpfile server
```

显式环境密钥优先于自动凭据。服务器保留 `.env` 和 RSA 私钥；客户端只复制共享密钥和 `server-public.pem`，绝不能复制服务器私钥。程序仍会自动加载当前目录的 `.env`，但密钥配置必须放在共享根目录之外；也可以通过 `UDPFILE_ENV=/path/to/config.env` 指定配置文件。

真实 `.env` 和 `keys/` 已被 `.gitignore` 排除；仓库中的 `.env.example` 不包含可用秘密。

## 从本地网页下载

假设目标服务器 IP 是 `192.168.1.20`，需要共享 `/srv/share`。目标电脑只需启动 UDP 文件服务器：

```bash
# 目标服务器：在共享目录启动，只开放 UDP 30033
cd /srv/share
udpfile server
```

在本地电脑启动 Web 助手：

```bash
udpfile client
```

然后用本地浏览器打开：

```text
http://127.0.0.1:8080
```

在页面中输入目标服务器 IP、UDP 端口和目录。首次连接还需粘贴服务端显示的配对令牌；成功后本机会自动保存，后续留空即可。浏览器最终下载 `2026.tar.gz`；跨电脑的请求、分片、重传和文件内容全部走 UDP，本地 HTTP 仅存在于浏览器与 `127.0.0.1` 上的助手之间。

解压下载结果：

```bash
tar -xzf 2026.tar.gz
```

`udpfile client` 强制只监听 `127.0.0.1`、`::1` 或 `localhost`，并使用页面令牌与 Host 校验阻止其他网页借本机接口发起下载。原来的 `udpfile web` 仍作为兼容别名可用。浏览器下载文件的最终保存位置由浏览器设置决定。

## 命令行客户端下载

不使用浏览器时，可以直接运行 UDP 客户端：

```bash
# 目标服务器
cd /srv/share
udpfile server

# 本地客户端首次连接
udpfile download \
  -server 192.168.1.20:30033 \
  -path photos/2026
```

`-path` 必须是相对于服务端共享根目录的目录路径，也可以用 `.` 请求根目录本身。省略 `-out` 时，结果默认解压到当前工作目录下的同名子目录，例如上例保存为 `./2026`；请求 `.` 时保存为 `./shared`。目标目录必须尚不存在，失败不会留下半成品目录。

## 网络要求

目标服务器默认监听所有网卡的 UDP `30033`。需要在目标服务器防火墙开放 `30033/udp`，无需开放 TCP 端口，也不需要在目标服务器运行 HTTP 服务。不希望暴露到所有网卡时，可显式使用 `udpfile server -addr 127.0.0.1:30033`。

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
udpfile server:
  -addr          监听地址，默认 0.0.0.0:30033
  -root          共享根目录，默认当前目录
  -max-bytes     单次请求的源文件总大小上限
  -max-sessions  最大并发会话数
  -session-ttl   临时归档保留时间
  -temp-dir      临时归档目录
  -show-pairing-token 重新显示自动凭据的配对令牌

udpfile client（udpfile web 是兼容别名）:
  -listen        本地页面地址，默认 127.0.0.1:8080，只允许回环地址
  -server        页面中预填的目标服务器 IP
  -port          页面中预填的目标 UDP 端口，默认 30033
  -timeout       单次 UDP 下载超时，默认 10m
  -retry         UDP 单包重试间隔，默认 300ms
  -max-archive   浏览器下载的最大压缩包大小
  -max-downloads 最大并发浏览器下载数，默认 2
  -temp-dir      下载过程中使用的临时目录

udpfile download:
  -server        服务器地址，默认 127.0.0.1:30033
  -path          服务端根目录下的相对目录（必填）
  -out           本地输出目录，默认当前目录下的远端同名子目录
  -timeout       整体传输超时，默认 10m
  -retry         单包重试间隔，默认 300ms
  -max-archive   接受的最大压缩包大小
  -pair-file     从权限为 0600 的文件或标准输入读取首次配对令牌

udpfile keygen:
  -env           环境配置输出路径，默认系统配置目录/manual/.env
  -keys          RSA 密钥输出目录，默认系统配置目录/manual/keys
  -rsa-bits      RSA 密钥位数，允许 2048 至 4096，默认 3072
```

## 测试

```bash
go test ./...
```
