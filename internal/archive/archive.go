package archive

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Info struct {
	Size   int64
	SHA256 [sha256.Size]byte
}

// Create writes the contents of requestedDirectory, relative to root, to a
// gzip-compressed tar archive. Symbolic links and non-regular files are rejected.
func Create(root, requestedDirectory, archivePath string, maxSourceBytes int64) (result Info, err error) {
	source, err := resolveDirectory(root, requestedDirectory)
	if err != nil {
		return Info{}, err
	}
	archiveAbsolute, err := filepath.Abs(archivePath)
	if err != nil {
		return Info{}, fmt.Errorf("resolve archive output: %w", err)
	}
	archiveParent, err := filepath.EvalSymlinks(filepath.Dir(archiveAbsolute))
	if err != nil {
		return Info{}, fmt.Errorf("resolve archive output directory: %w", err)
	}
	archiveAbsolute = filepath.Join(archiveParent, filepath.Base(archiveAbsolute))
	if pathIsWithin(source, archiveAbsolute) {
		return Info{}, errors.New("archive output must not be inside the source directory")
	}

	output, err := os.Create(archiveAbsolute)
	if err != nil {
		return Info{}, fmt.Errorf("create archive: %w", err)
	}
	succeeded := false
	defer func() {
		if closeErr := output.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close archive: %w", closeErr)
		}
		if !succeeded || err != nil {
			_ = os.Remove(archiveAbsolute)
		}
	}()

	hash := sha256.New()
	gzipWriter := gzip.NewWriter(io.MultiWriter(output, hash))
	tarWriter := tar.NewWriter(gzipWriter)
	var sourceBytes int64

	walkErr := filepath.Walk(source, func(currentPath string, fileInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if currentPath == source {
			return nil
		}
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not supported: %s", currentPath)
		}
		if !fileInfo.IsDir() && !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("special files are not supported: %s", currentPath)
		}
		if fileInfo.Mode().IsRegular() {
			sourceBytes += fileInfo.Size()
			if maxSourceBytes > 0 && sourceBytes > maxSourceBytes {
				return fmt.Errorf("directory exceeds maximum source size of %d bytes", maxSourceBytes)
			}
		}

		relativeName, relErr := filepath.Rel(source, currentPath)
		if relErr != nil {
			return relErr
		}
		header, headerErr := tar.FileInfoHeader(fileInfo, "")
		if headerErr != nil {
			return headerErr
		}
		header.Name = filepath.ToSlash(relativeName)
		if headerErr = tarWriter.WriteHeader(header); headerErr != nil {
			return headerErr
		}
		if !fileInfo.Mode().IsRegular() {
			return nil
		}

		input, openErr := os.Open(currentPath)
		if openErr != nil {
			return openErr
		}
		_, copyErr := io.Copy(tarWriter, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if walkErr != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		return Info{}, fmt.Errorf("archive directory: %w", walkErr)
	}
	if err = tarWriter.Close(); err != nil {
		return Info{}, fmt.Errorf("finish tar archive: %w", err)
	}
	if err = gzipWriter.Close(); err != nil {
		return Info{}, fmt.Errorf("finish compressed archive: %w", err)
	}
	if err = output.Sync(); err != nil {
		return Info{}, fmt.Errorf("sync archive: %w", err)
	}
	stat, err := output.Stat()
	if err != nil {
		return Info{}, fmt.Errorf("stat archive: %w", err)
	}
	succeeded = true
	var checksum [sha256.Size]byte
	copy(checksum[:], hash.Sum(nil))
	return Info{Size: stat.Size(), SHA256: checksum}, nil
}

func resolveDirectory(root, requestedDirectory string) (string, error) {
	if requestedDirectory == "" || filepath.IsAbs(requestedDirectory) {
		return "", errors.New("requested path must be a non-empty relative path")
	}
	cleanRequest := filepath.Clean(requestedDirectory)
	if relativePathEscapesRoot(cleanRequest) {
		return "", errors.New("requested path escapes the configured root")
	}

	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbsolute)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	targetResolved, err := filepath.EvalSymlinks(filepath.Join(rootResolved, cleanRequest))
	if err != nil {
		return "", fmt.Errorf("resolve requested path: %w", err)
	}
	relativeToRoot, err := filepath.Rel(rootResolved, targetResolved)
	if err != nil || relativePathEscapesRoot(relativeToRoot) {
		return "", errors.New("requested path escapes the configured root")
	}
	stat, err := os.Stat(targetResolved)
	if err != nil {
		return "", fmt.Errorf("stat requested path: %w", err)
	}
	if !stat.IsDir() {
		return "", errors.New("requested path is not a directory")
	}
	return targetResolved, nil
}

func pathIsWithin(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && !relativePathEscapesRoot(relative)
}

func relativePathEscapesRoot(relative string) bool {
	return relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// Extract safely expands an archive into a new destination directory. The
// destination must not already exist; extraction is committed with a rename so
// callers never observe a partially restored directory.
func Extract(archivePath, destination string) (err error) {
	if _, statErr := os.Lstat(destination); statErr == nil {
		return fmt.Errorf("destination already exists: %s", destination)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect destination: %w", statErr)
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create destination parent: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, "."+filepath.Base(destination)+".partial-")
	if err != nil {
		return fmt.Errorf("create temporary destination: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(temporary)
		}
	}()

	input, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer input.Close()
	gzipReader, err := gzip.NewReader(input)
	if err != nil {
		return fmt.Errorf("read compressed archive: %w", err)
	}
	defer gzipReader.Close()

	type directoryMetadata struct {
		path    string
		mode    os.FileMode
		modTime time.Time
	}
	var directories []directoryMetadata
	tarReader := tar.NewReader(gzipReader)
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read tar entry: %w", nextErr)
		}
		entryPath, pathErr := safeArchivePath(temporary, header.Name)
		if pathErr != nil {
			return pathErr
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(entryPath, 0o755); err != nil {
				return fmt.Errorf("create directory %q: %w", header.Name, err)
			}
			directories = append(directories, directoryMetadata{entryPath, os.FileMode(header.Mode).Perm(), header.ModTime})
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(entryPath), 0o755); err != nil {
				return fmt.Errorf("create parent for %q: %w", header.Name, err)
			}
			output, openErr := os.OpenFile(entryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if openErr != nil {
				return fmt.Errorf("create file %q: %w", header.Name, openErr)
			}
			_, copyErr := io.CopyN(output, tarReader, header.Size)
			closeErr := output.Close()
			if copyErr != nil {
				return fmt.Errorf("write file %q: %w", header.Name, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close file %q: %w", header.Name, closeErr)
			}
			if chmodErr := os.Chmod(entryPath, os.FileMode(header.Mode).Perm()); chmodErr != nil {
				return fmt.Errorf("set permissions on %q: %w", header.Name, chmodErr)
			}
			if chtimesErr := os.Chtimes(entryPath, header.ModTime, header.ModTime); chtimesErr != nil {
				return fmt.Errorf("set time on %q: %w", header.Name, chtimesErr)
			}
		default:
			return fmt.Errorf("unsupported archive entry type for %q", header.Name)
		}
	}

	sort.Slice(directories, func(i, j int) bool {
		return strings.Count(directories[i].path, string(filepath.Separator)) > strings.Count(directories[j].path, string(filepath.Separator))
	})
	for _, directory := range directories {
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return fmt.Errorf("set directory permissions: %w", err)
		}
		if err := os.Chtimes(directory.path, directory.modTime, directory.modTime); err != nil {
			return fmt.Errorf("set directory time: %w", err)
		}
	}

	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("commit extracted directory: %w", err)
	}
	return nil
}

func safeArchivePath(root, name string) (string, error) {
	if name == "" || path.IsAbs(name) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	cleanName := path.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return filepath.Join(root, filepath.FromSlash(cleanName)), nil
}
