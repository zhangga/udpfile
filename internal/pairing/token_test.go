package pairing_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"udpfile/internal/pairing"
)

func TestTokenRoundTripCarriesSecretAndServerIdentity(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, 32)
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	token, err := pairing.Encode(secret, &identity.PublicKey)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !strings.HasPrefix(token, "UDF2-") {
		t.Fatalf("Encode() token = %q, want UDF2- prefix", token)
	}

	decodedSecret, decodedIdentity, err := pairing.Decode(token)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !bytes.Equal(decodedSecret, secret) {
		t.Fatal("Decode() returned a different shared secret")
	}
	if decodedIdentity.N.Cmp(identity.N) != 0 || decodedIdentity.E != identity.E {
		t.Fatal("Decode() returned a different RSA identity")
	}
}

func TestTokenRejectsTypingError(t *testing.T) {
	secret := bytes.Repeat([]byte{0x31}, 32)
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token, err := pairing.Encode(secret, &identity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, position := range []int{len(token) / 2, len(token) - 1} {
		replacement := byte('A')
		if token[position] == replacement {
			replacement = 'B'
		}
		tampered := token[:position] + string(replacement) + token[position+1:]
		if _, _, err := pairing.Decode(tampered); err == nil {
			t.Fatalf("Decode() accepted a pairing token modified at byte %d", position)
		}
	}
}

func TestTokenRejectsInvalidCredentials(t *testing.T) {
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairing.Encode([]byte("too short"), &identity.PublicKey); err == nil {
		t.Fatal("Encode() accepted a short shared secret")
	}
	if _, err := pairing.Encode(bytes.Repeat([]byte{1}, 32), nil); err == nil {
		t.Fatal("Encode() accepted a nil server identity")
	}
}
