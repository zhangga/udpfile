package appconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	PrivateKeyFilename = "server-private.pem"
	PublicKeyFilename  = "server-public.pem"
	MinimumRSABits     = 2048
	MaximumRSABits     = 4096
)

type KeyMaterial struct {
	PrivateKeyPath string
	PublicKeyPath  string
	SharedSecret   string
}

func LoadServerCredentials() ([]byte, *rsa.PrivateKey, error) {
	sharedSecret, err := DecodeSharedSecret(os.Getenv("UDPFILE_SHARED_SECRET"))
	if err != nil {
		return nil, nil, err
	}
	identity, err := LoadRSAPrivateKey(String("UDPFILE_RSA_PRIVATE_KEY", filepath.Join("keys", PrivateKeyFilename)))
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, identity, nil
}

func LoadClientCredentials() ([]byte, *rsa.PublicKey, error) {
	sharedSecret, err := DecodeSharedSecret(os.Getenv("UDPFILE_SHARED_SECRET"))
	if err != nil {
		return nil, nil, err
	}
	identity, err := LoadRSAPublicKey(String("UDPFILE_RSA_PUBLIC_KEY", filepath.Join("keys", PublicKeyFilename)))
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, identity, nil
}

func GenerateKeyMaterial(directory string, rsaBits int) (KeyMaterial, error) {
	if rsaBits < MinimumRSABits || rsaBits > MaximumRSABits {
		return KeyMaterial{}, fmt.Errorf("RSA key must be between %d and %d bits", MinimumRSABits, MaximumRSABits)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return KeyMaterial{}, fmt.Errorf("create key directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return KeyMaterial{}, fmt.Errorf("secure key directory: %w", err)
	}
	privatePath := filepath.Join(directory, PrivateKeyFilename)
	publicPath := filepath.Join(directory, PublicKeyFilename)
	if _, err := os.Lstat(privatePath); err == nil {
		return KeyMaterial{}, fmt.Errorf("key already exists: %s", privatePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return KeyMaterial{}, err
	}
	if _, err := os.Lstat(publicPath); err == nil {
		return KeyMaterial{}, fmt.Errorf("key already exists: %s", publicPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return KeyMaterial{}, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate RSA key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("encode RSA private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("encode RSA public key: %w", err)
	}
	if err := writeExclusivePEM(privatePath, 0o600, "PRIVATE KEY", privateDER); err != nil {
		return KeyMaterial{}, err
	}
	if err := writeExclusivePEM(publicPath, 0o644, "PUBLIC KEY", publicDER); err != nil {
		_ = os.Remove(privatePath)
		return KeyMaterial{}, err
	}
	if err := syncDirectory(directory); err != nil {
		_ = os.Remove(privatePath)
		_ = os.Remove(publicPath)
		return KeyMaterial{}, fmt.Errorf("sync key directory: %w", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		_ = os.Remove(privatePath)
		_ = os.Remove(publicPath)
		return KeyMaterial{}, fmt.Errorf("generate shared secret: %w", err)
	}
	return KeyMaterial{
		PrivateKeyPath: privatePath,
		PublicKeyPath:  publicPath,
		SharedSecret:   base64.RawStdEncoding.EncodeToString(secret),
	}, nil
}

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	if err := validateConfigurationFile(path, true); err != nil {
		return nil, err
	}
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	var privateKey *rsa.PrivateKey
	if parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
		var ok bool
		privateKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
	} else {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
	}
	if privateKey.N.BitLen() < MinimumRSABits || privateKey.N.BitLen() > MaximumRSABits {
		return nil, fmt.Errorf("RSA private key must be between %d and %d bits", MinimumRSABits, MaximumRSABits)
	}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("validate RSA private key: %w", err)
	}
	return privateKey, nil
}

func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	var publicKey *rsa.PublicKey
	if parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes); parseErr == nil {
		var ok bool
		publicKey, ok = parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}
	} else {
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA public key: %w", err)
		}
	}
	if publicKey.N.BitLen() < MinimumRSABits || publicKey.N.BitLen() > MaximumRSABits {
		return nil, fmt.Errorf("RSA public key must be between %d and %d bits", MinimumRSABits, MaximumRSABits)
	}
	return publicKey, nil
}

func writeExclusivePEM(path string, mode os.FileMode, blockType string, der []byte) error {
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := pem.Encode(output, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = output.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

func readPEM(path string) (*pem.Block, error) {
	if err := validateConfigurationFile(path, false); err != nil {
		return nil, err
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, remainder := pem.Decode(contents)
	if block == nil || len(remainder) != 0 {
		return nil, fmt.Errorf("%s does not contain exactly one PEM block", path)
	}
	return block, nil
}
