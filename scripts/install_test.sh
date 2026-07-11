#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/udpfile-install-test.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

source_directory="$temporary_directory/source"
install_home="$temporary_directory/home"
install_directory="$install_home/.local/bin"
mkdir -p "$source_directory" "$install_home"
cp "$repository_root/dist/linux-amd64/udpfile" "$source_directory/udpfile"
cp "$repository_root/dist/linux-amd64/SHA256SUMS" "$source_directory/SHA256SUMS"

run_installer() {
	UDPFILE_OS=Linux \
	UDPFILE_ARCH=x86_64 \
	UDPFILE_DOWNLOAD_BASE="file://$source_directory" \
	UDPFILE_INSTALL_DIR="$install_directory" \
	sh "$repository_root/install.sh"
}

run_installer
cmp "$repository_root/dist/linux-amd64/udpfile" "$install_directory/udpfile"
test -x "$install_directory/udpfile"

printf '\ncorrupted\n' >>"$source_directory/udpfile"
if run_installer >"$temporary_directory/corrupt.log" 2>&1; then
	echo "损坏的下载文件不应通过安装" >&2
	exit 1
fi
cmp "$repository_root/dist/linux-amd64/udpfile" "$install_directory/udpfile"

if UDPFILE_OS=Linux UDPFILE_ARCH=aarch64 sh "$repository_root/install.sh" >"$temporary_directory/arch.log" 2>&1; then
	echo "不支持的架构不应通过安装" >&2
	exit 1
fi

echo "install.sh tests passed"
