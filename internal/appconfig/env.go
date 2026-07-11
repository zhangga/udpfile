package appconfig

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"
)

const DefaultEnvFile = ".env"

func LoadDefault() error {
	path := os.Getenv("UDPFILE_ENV")
	if path == "" {
		path = DefaultEnvFile
	}
	if err := LoadFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// LoadFile loads KEY=VALUE pairs without replacing variables already present
// in the process environment. This gives precedence to explicit environment
// variables while command-line flags can still override both.
func LoadFile(path string) error {
	if err := validateConfigurationFile(path, true); err != nil {
		return err
	}
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()

	scanner := bufio.NewScanner(input)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, rawValue, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !validEnvironmentKey(key) {
			return fmt.Errorf("%s:%d: invalid environment assignment", path, lineNumber)
		}
		value, err := parseEnvironmentValue(strings.TrimSpace(rawValue))
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func validateConfigurationFile(path string, containsSecrets bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file, not a symlink", path)
	}
	if containsSecrets && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s contains secrets and must not be accessible by group or other users; run chmod 600 %s", path, path)
	}
	return nil
}

func DecodeSharedSecret(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("UDPFILE_SHARED_SECRET is required")
	}
	secret, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		secret, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, errors.New("UDPFILE_SHARED_SECRET must be base64")
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("UDPFILE_SHARED_SECRET must decode to exactly 32 bytes, got %d", len(secret))
	}
	return secret, nil
}

func String(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func Int(key string, fallback int) (int, error) {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return parsed, nil
}

func parseEnvironmentValue(value string) (string, error) {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		parsed, err := strconv.Unquote(value)
		if err != nil {
			return "", fmt.Errorf("invalid quoted value: %w", err)
		}
		return parsed, nil
	}
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1], nil
	}
	return value, nil
}

func validEnvironmentKey(key string) bool {
	if key == "" {
		return false
	}
	for index, character := range key {
		if character == '_' || unicode.IsLetter(character) || index > 0 && unicode.IsDigit(character) {
			continue
		}
		return false
	}
	return true
}
