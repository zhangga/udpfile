#!/bin/sh

set -eu

program_name=udpfile
repository=zhangga/udpfile

log() {
	printf '%s\n' "udpfile installer: $*"
}

die() {
	printf '%s\n' "udpfile installer: $*" >&2
	exit 1
}

command_exists() {
	command -v "$1" >/dev/null 2>&1
}

show_help() {
	cat <<'EOF'
udpfile Linux 一键安装器

用法:
  curl -fsSL https://raw.githubusercontent.com/zhangga/udpfile/main/install.sh | sh

可选环境变量:
  UDPFILE_INSTALL_DIR    安装目录，默认 /usr/local/bin
  UDPFILE_REF            Git 分支、标签或提交，默认 main
  UDPFILE_DOWNLOAD_BASE  自定义产物下载地址
EOF
}

case "${1:-}" in
	"") ;;
	-h | --help)
		show_help
		exit 0
		;;
	*) die "未知参数：$1" ;;
esac

operating_system=${UDPFILE_OS:-$(uname -s)}
machine_architecture=${UDPFILE_ARCH:-$(uname -m)}

case "$operating_system" in
	Linux | linux) ;;
	*) die "当前仅支持 Linux，检测到：$operating_system" ;;
esac

case "$machine_architecture" in
	x86_64 | amd64)
		platform=linux-amd64
		;;
	*) die "当前仅支持 Linux x86-64，检测到：$machine_architecture" ;;
esac

install_directory=${UDPFILE_INSTALL_DIR:-/usr/local/bin}
git_reference=${UDPFILE_REF:-main}
download_base=${UDPFILE_DOWNLOAD_BASE:-https://raw.githubusercontent.com/$repository/$git_reference/dist/$platform}

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/udpfile-install.XXXXXX") || die "无法创建临时目录"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

download() {
	url=$1
	destination=$2
	if command_exists curl; then
		curl -fsSL --retry 3 --connect-timeout 15 -o "$destination" "$url"
	elif command_exists wget; then
		wget -q -O "$destination" "$url"
	else
		die "需要 curl 或 wget 才能下载安装包"
	fi
}

log "下载 $platform 产物"
download "$download_base/$program_name" "$temporary_directory/$program_name"
download "$download_base/SHA256SUMS" "$temporary_directory/SHA256SUMS"

log "验证 SHA-256"
if command_exists sha256sum; then
	(cd "$temporary_directory" && sha256sum -c SHA256SUMS)
elif command_exists shasum; then
	(cd "$temporary_directory" && shasum -a 256 -c SHA256SUMS)
else
	die "缺少 sha256sum，无法验证下载文件"
fi

if [ -e "$install_directory" ] && [ ! -d "$install_directory" ]; then
	die "安装路径不是目录：$install_directory"
fi
if ! command_exists install; then
	die "缺少 install 命令"
fi

needs_sudo=true
writable_ancestor=$install_directory
while [ ! -e "$writable_ancestor" ]; do
	parent_directory=$(dirname "$writable_ancestor")
	[ "$parent_directory" != "$writable_ancestor" ] || break
	writable_ancestor=$parent_directory
done
if [ "$(id -u)" -eq 0 ]; then
	needs_sudo=false
elif [ -d "$install_directory" ] && [ -w "$install_directory" ]; then
	needs_sudo=false
elif [ ! -e "$install_directory" ] && [ -d "$writable_ancestor" ] && [ -w "$writable_ancestor" ]; then
	needs_sudo=false
fi

if [ "$needs_sudo" = true ]; then
	command_exists sudo || die "写入 $install_directory 需要管理员权限，但系统没有 sudo；请用 root 运行或设置 UDPFILE_INSTALL_DIR"
	log "安装到 $install_directory（需要 sudo）"
	sudo install -d "$install_directory"
	sudo install -m 0755 "$temporary_directory/$program_name" "$install_directory/$program_name"
else
	log "安装到 $install_directory"
	install -d "$install_directory"
	install -m 0755 "$temporary_directory/$program_name" "$install_directory/$program_name"
fi

log "安装完成：$install_directory/$program_name"
log "运行 '$install_directory/$program_name help' 查看可用命令"
