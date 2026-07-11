package pairing

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	tokenPrefix  = "UDF2-"
	tokenVersion = byte(1)
	secretSize   = 32
	checksumSize = 8
)

func Encode(sharedSecret []byte, serverIdentity *rsa.PublicKey) (string, error) {
	if len(sharedSecret) != secretSize {
		return "", errors.New("pairing shared secret must be exactly 32 bytes")
	}
	if serverIdentity == nil || serverIdentity.N.BitLen() < 2048 || serverIdentity.N.BitLen() > 4096 {
		return "", errors.New("pairing RSA identity must be between 2048 and 4096 bits")
	}
	der, err := x509.MarshalPKIXPublicKey(serverIdentity)
	if err != nil {
		return "", fmt.Errorf("encode pairing RSA identity: %w", err)
	}
	if len(der) > 65535 {
		return "", errors.New("pairing RSA identity is too large")
	}
	body := make([]byte, 1+secretSize+2+len(der))
	body[0] = tokenVersion
	copy(body[1:1+secretSize], sharedSecret)
	binary.BigEndian.PutUint16(body[1+secretSize:1+secretSize+2], uint16(len(der)))
	copy(body[1+secretSize+2:], der)
	checksum := sha256.Sum256(body)
	payload := append(body, checksum[:checksumSize]...)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func Decode(token string) ([]byte, *rsa.PublicKey, error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, tokenPrefix) {
		return nil, nil, errors.New("pairing token must start with UDF2-")
	}
	encodedPayload := strings.TrimPrefix(token, tokenPrefix)
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, nil, errors.New("pairing token is not valid base64url")
	}
	if base64.RawURLEncoding.EncodeToString(payload) != encodedPayload {
		return nil, nil, errors.New("pairing token is not canonical base64url")
	}
	minimumSize := 1 + secretSize + 2 + 1 + checksumSize
	if len(payload) < minimumSize {
		return nil, nil, errors.New("pairing token is too short")
	}
	body := payload[:len(payload)-checksumSize]
	suppliedChecksum := payload[len(payload)-checksumSize:]
	expectedChecksum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(suppliedChecksum, expectedChecksum[:checksumSize]) != 1 {
		return nil, nil, errors.New("pairing token checksum does not match")
	}
	if body[0] != tokenVersion {
		return nil, nil, errors.New("pairing token version is not supported")
	}
	identityLength := int(binary.BigEndian.Uint16(body[1+secretSize : 1+secretSize+2]))
	identityOffset := 1 + secretSize + 2
	if identityLength == 0 || identityOffset+identityLength != len(body) {
		return nil, nil, errors.New("pairing token RSA identity length is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(body[identityOffset:])
	if err != nil {
		return nil, nil, errors.New("pairing token RSA identity is invalid")
	}
	identity, ok := parsed.(*rsa.PublicKey)
	if !ok || identity.N.BitLen() < 2048 || identity.N.BitLen() > 4096 {
		return nil, nil, errors.New("pairing token does not contain a supported RSA identity")
	}
	secret := append([]byte(nil), body[1:1+secretSize]...)
	return secret, identity, nil
}
