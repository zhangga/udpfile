package archive

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAndExtractPreservesDirectoryContents(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "documents")
	mustMkdirAll(t, filepath.Join(source, "nested"))
	mustWriteFile(t, filepath.Join(source, "hello.txt"), []byte("hello over udp\n"))
	mustWriteFile(t, filepath.Join(source, "nested", "data.bin"), []byte{0, 1, 2, 3, 255})
	mustMkdirAll(t, filepath.Join(source, "empty"))

	archivePath := filepath.Join(t.TempDir(), "transfer.tar.gz")
	info, err := Create(root, "documents", archivePath, 1<<20)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if info.Size == 0 || info.SHA256 == [32]byte{} {
		t.Fatalf("Create() returned incomplete info: %+v", info)
	}

	destination := filepath.Join(t.TempDir(), "received")
	if err := Extract(archivePath, destination); err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	assertFileContents(t, filepath.Join(destination, "hello.txt"), []byte("hello over udp\n"))
	assertFileContents(t, filepath.Join(destination, "nested", "data.bin"), []byte{0, 1, 2, 3, 255})
	if stat, err := os.Stat(filepath.Join(destination, "empty")); err != nil || !stat.IsDir() {
		t.Fatalf("empty directory was not restored: stat=%v err=%v", stat, err)
	}
}

func TestCreateRejectsPathsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWriteFile(t, filepath.Join(outside, "secret.txt"), []byte("secret"))

	_, err := Create(root, filepath.Join("..", filepath.Base(outside)), filepath.Join(t.TempDir(), "x.tar.gz"), 1<<20)
	if err == nil {
		t.Fatal("Create() accepted a path outside the configured root")
	}
}

func TestCreateRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(root, "target.txt"), []byte("target"))
	if err := os.Symlink(filepath.Join(root, "target.txt"), filepath.Join(source, "link")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	_, err := Create(root, "source", filepath.Join(t.TempDir(), "x.tar.gz"), 1<<20)
	if err == nil {
		t.Fatal("Create() accepted a symbolic link")
	}
}

func TestCreateRejectsArchiveInsideSourceDirectory(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(source, "hello.txt"), []byte("hello"))

	_, err := Create(root, "source", filepath.Join(source, "transfer.tar.gz"), 1<<20)
	if err == nil {
		t.Fatal("Create() accepted an output archive inside the source directory")
	}
}

func TestExtractRejectsPathTraversal(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "malicious.tar.gz")
	output, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	gzipWriter := gzip.NewWriter(output)
	tarWriter := tar.NewWriter(gzipWriter)
	data := []byte("escaped")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "../escaped.txt", Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tarWriter.Write(data); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar Close() error = %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("archive Close() error = %v", err)
	}

	parent := t.TempDir()
	destination := filepath.Join(parent, "received")
	if err := Extract(archivePath, destination); err == nil {
		t.Fatal("Extract() accepted an archive path that escaped the destination")
	}
	if _, err := os.Stat(filepath.Join(parent, "escaped.txt")); !os.IsNotExist(err) {
		t.Fatalf("path traversal created a file outside destination: %v", err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func assertFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents of %q = %v, want %v", path, got, want)
	}
}
