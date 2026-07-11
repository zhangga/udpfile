package secure

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"udpfile/internal/protocol"
)

func TestHandshakeCreatesAuthenticatedBidirectionalSession(t *testing.T) {
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	secret := bytes.Repeat([]byte{0x5a}, 32)
	id := protocol.RequestID{1, 3, 5, 7}

	clientHandshake, clientHello, err := NewClientHandshake(id, secret)
	if err != nil {
		t.Fatalf("NewClientHandshake() error = %v", err)
	}
	serverHello, serverSession, err := AcceptClientHandshake(clientHello, secret, identity)
	if err != nil {
		t.Fatalf("AcceptClientHandshake() error = %v", err)
	}
	clientSession, err := clientHandshake.Complete(serverHello, &identity.PublicKey)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}

	clientMessage, err := protocol.EncodeRequest(id, "documents/private")
	if err != nil {
		t.Fatalf("EncodeRequest() error = %v", err)
	}
	sealedClientMessage, err := clientSession.Seal(clientMessage)
	if err != nil {
		t.Fatalf("client Seal() error = %v", err)
	}
	openedClientMessage, err := serverSession.Open(sealedClientMessage)
	if err != nil {
		t.Fatalf("server Open() error = %v", err)
	}
	if !bytes.Equal(openedClientMessage, clientMessage) {
		t.Fatal("server opened different client plaintext")
	}
	if _, err := serverSession.Open(sealedClientMessage); err == nil {
		t.Fatal("server accepted a replayed encrypted packet")
	}

	serverMessage, err := protocol.EncodeMeta(id, protocol.Meta{Size: 1120, Chunks: 1, ChunkSize: protocol.ChunkSize})
	if err != nil {
		t.Fatalf("EncodeMeta() error = %v", err)
	}
	sealedServerMessage, err := serverSession.Seal(serverMessage)
	if err != nil {
		t.Fatalf("server Seal() error = %v", err)
	}
	openedServerMessage, err := clientSession.Open(sealedServerMessage)
	if err != nil {
		t.Fatalf("client Open() error = %v", err)
	}
	if !bytes.Equal(openedServerMessage, serverMessage) {
		t.Fatal("client opened different server plaintext")
	}
}

func TestHandshakeRejectsWrongSharedSecretAndServerIdentity(t *testing.T) {
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	id := protocol.RequestID{9, 9, 9}
	secret := bytes.Repeat([]byte{0x11}, 32)
	handshake, clientHello, err := NewClientHandshake(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcceptClientHandshake(clientHello, bytes.Repeat([]byte{0x22}, 32), identity); err == nil {
		t.Fatal("AcceptClientHandshake() accepted the wrong shared secret")
	}
	serverHello, _, err := AcceptClientHandshake(clientHello, secret, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshake.Complete(serverHello, &wrongIdentity.PublicKey); err == nil {
		t.Fatal("Complete() accepted a server signed by the wrong RSA key")
	}
}

func TestEncryptedPacketRejectsTampering(t *testing.T) {
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0xa5}, 32)
	id := protocol.RequestID{2, 4, 6, 8}
	handshake, hello, err := NewClientHandshake(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	serverHello, serverSession, err := AcceptClientHandshake(hello, secret, identity)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := handshake.Complete(serverHello, &identity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := protocol.EncodeGet(id, 3)
	packet, err := clientSession.Seal(inner)
	if err != nil {
		t.Fatal(err)
	}
	validPacket := append([]byte(nil), packet...)
	packet[len(packet)-1] ^= 0x80
	if _, err := serverSession.Open(packet); err == nil {
		t.Fatal("Open() accepted a tampered ciphertext")
	}
	if _, err := serverSession.Open(validPacket); err != nil {
		t.Fatalf("tampered packet advanced replay state: %v", err)
	}
}
