package secure

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"

	"udpfile/internal/protocol"
)

var (
	clientAuthenticationLabel = []byte("udpfile-v2 client authentication")
	transcriptLabel           = []byte("udpfile-v2 X25519 RSA-PSS handshake")
	hkdfSaltLabel             = []byte("udpfile-v2 HKDF salt")
	hkdfInfoLabel             = []byte("udpfile-v2 AES-256-GCM keys")
)

const (
	replayWindowSize  = 256
	replayWindowWords = replayWindowSize / 64
)

type ClientHandshake struct {
	id          protocol.RequestID
	privateKey  *ecdh.PrivateKey
	publicKey   [32]byte
	clientNonce [32]byte
	secret      [32]byte
}

type Session struct {
	id               protocol.RequestID
	outbound         cipher.AEAD
	inbound          cipher.AEAD
	outboundMu       sync.Mutex
	outboundSequence uint64
	inboundMu        sync.Mutex
	inboundSequence  uint64
	inboundSeen      [replayWindowWords]uint64
}

func NewClientHandshake(id protocol.RequestID, sharedSecret []byte) (*ClientHandshake, []byte, error) {
	secret, err := fixedSecret(sharedSecret)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client X25519 key: %w", err)
	}
	client := &ClientHandshake{id: id, privateKey: privateKey, secret: secret}
	copy(client.publicKey[:], privateKey.PublicKey().Bytes())
	if _, err := rand.Read(client.clientNonce[:]); err != nil {
		return nil, nil, fmt.Errorf("generate client nonce: %w", err)
	}
	authentication := clientAuthentication(secret, id, client.publicKey, client.clientNonce)
	packet, err := protocol.EncodeClientHello(id, client.publicKey[:], client.clientNonce[:], authentication[:])
	if err != nil {
		return nil, nil, err
	}
	return client, packet, nil
}

func AcceptClientHandshake(clientHello []byte, sharedSecret []byte, identity *rsa.PrivateKey) ([]byte, *Session, error) {
	secret, err := fixedSecret(sharedSecret)
	if err != nil {
		return nil, nil, err
	}
	if identity == nil || identity.N.BitLen() < 2048 || identity.N.BitLen() > 4096 {
		return nil, nil, errors.New("server RSA identity must be between 2048 and 4096 bits")
	}
	id, clientPublicBytes, clientNonce, suppliedAuthentication, err := protocol.DecodeClientHello(clientHello)
	if err != nil {
		return nil, nil, err
	}
	expectedAuthentication := clientAuthentication(secret, id, clientPublicBytes, clientNonce)
	if !hmac.Equal(suppliedAuthentication[:], expectedAuthentication[:]) {
		return nil, nil, errors.New("client authentication failed")
	}
	clientPublicKey, err := ecdh.X25519().NewPublicKey(clientPublicBytes[:])
	if err != nil {
		return nil, nil, errors.New("invalid client X25519 public key")
	}
	serverPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server X25519 key: %w", err)
	}
	var serverPublicBytes, serverNonce [32]byte
	copy(serverPublicBytes[:], serverPrivateKey.PublicKey().Bytes())
	if _, err := rand.Read(serverNonce[:]); err != nil {
		return nil, nil, fmt.Errorf("generate server nonce: %w", err)
	}
	sharedKey, err := serverPrivateKey.ECDH(clientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("complete server ECDH: %w", err)
	}
	transcript := handshakeTranscript(id, clientPublicBytes, clientNonce, serverPublicBytes, serverNonce)
	signature, err := rsa.SignPSS(rand.Reader, identity, crypto.SHA256, transcript[:], nil)
	if err != nil {
		return nil, nil, fmt.Errorf("sign server handshake: %w", err)
	}
	serverHello, err := protocol.EncodeServerHello(id, serverPublicBytes[:], serverNonce[:], signature)
	if err != nil {
		return nil, nil, err
	}
	clientKey, serverKey := deriveDirectionalKeys(sharedKey, secret, clientNonce, serverNonce, transcript)
	session, err := newSession(id, serverKey, clientKey)
	if err != nil {
		return nil, nil, err
	}
	return serverHello, session, nil
}

func (handshake *ClientHandshake) Complete(serverHello []byte, identity *rsa.PublicKey) (*Session, error) {
	if handshake == nil || handshake.privateKey == nil {
		return nil, errors.New("client handshake is not initialized")
	}
	if identity == nil || identity.N.BitLen() < 2048 || identity.N.BitLen() > 4096 {
		return nil, errors.New("server RSA public key must be between 2048 and 4096 bits")
	}
	id, serverPublicBytes, serverNonce, signature, err := protocol.DecodeServerHello(serverHello)
	if err != nil {
		return nil, err
	}
	if id != handshake.id {
		return nil, errors.New("server hello request ID does not match")
	}
	transcript := handshakeTranscript(id, handshake.publicKey, handshake.clientNonce, serverPublicBytes, serverNonce)
	if err := rsa.VerifyPSS(identity, crypto.SHA256, transcript[:], signature, nil); err != nil {
		return nil, errors.New("server RSA signature verification failed")
	}
	serverPublicKey, err := ecdh.X25519().NewPublicKey(serverPublicBytes[:])
	if err != nil {
		return nil, errors.New("invalid server X25519 public key")
	}
	sharedKey, err := handshake.privateKey.ECDH(serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("complete client ECDH: %w", err)
	}
	clientKey, serverKey := deriveDirectionalKeys(sharedKey, handshake.secret, handshake.clientNonce, serverNonce, transcript)
	return newSession(id, clientKey, serverKey)
}

func (session *Session) Seal(innerPacket []byte) ([]byte, error) {
	packetType, id, err := protocol.Header(innerPacket)
	if err != nil {
		return nil, fmt.Errorf("validate inner packet: %w", err)
	}
	if id != session.id || packetType < protocol.TypeRequest || packetType > protocol.TypeDone {
		return nil, errors.New("inner packet does not belong to secure session")
	}
	if len(innerPacket) > protocol.MaxInnerSize {
		return nil, errors.New("inner packet is too large for encrypted transport")
	}
	session.outboundMu.Lock()
	defer session.outboundMu.Unlock()
	if session.outboundSequence >= uint64(math.MaxUint32) {
		return nil, errors.New("encrypted session reached its packet limit")
	}
	session.outboundSequence++
	sequence := session.outboundSequence
	nonce := sequenceNonce(session.outbound.NonceSize(), sequence)
	associatedData := protocol.SecureAssociatedData(session.id, sequence)
	ciphertext := session.outbound.Seal(nil, nonce, innerPacket, associatedData)
	payload := make([]byte, 8+len(ciphertext))
	binary.BigEndian.PutUint64(payload[0:8], sequence)
	copy(payload[8:], ciphertext)
	return protocol.EncodeSecure(session.id, payload)
}

func (session *Session) Open(encryptedPacket []byte) ([]byte, error) {
	id, payload, err := protocol.DecodeSecure(encryptedPacket)
	if err != nil {
		return nil, err
	}
	if id != session.id {
		return nil, errors.New("encrypted packet request ID does not match session")
	}
	if len(payload) < 8+session.inbound.Overhead() {
		return nil, errors.New("encrypted packet is too short")
	}
	sequence := binary.BigEndian.Uint64(payload[0:8])
	if sequence == 0 || sequence > uint64(math.MaxUint32) {
		return nil, errors.New("encrypted packet sequence is invalid")
	}
	nonce := sequenceNonce(session.inbound.NonceSize(), sequence)
	associatedData := protocol.SecureAssociatedData(session.id, sequence)
	plaintext, err := session.inbound.Open(nil, nonce, payload[8:], associatedData)
	if err != nil {
		return nil, errors.New("encrypted packet authentication failed")
	}
	session.inboundMu.Lock()
	defer session.inboundMu.Unlock()
	if !session.acceptInboundSequence(sequence) {
		return nil, errors.New("encrypted packet replay detected")
	}
	packetType, innerID, err := protocol.Header(plaintext)
	if err != nil {
		return nil, errors.New("decrypted packet is malformed")
	}
	if innerID != session.id || packetType < protocol.TypeRequest || packetType > protocol.TypeDone {
		return nil, errors.New("decrypted packet does not belong to secure session")
	}
	return plaintext, nil
}

func (session *Session) acceptInboundSequence(sequence uint64) bool {
	if sequence > session.inboundSequence {
		shiftReplayWindow(&session.inboundSeen, sequence-session.inboundSequence)
		session.inboundSequence = sequence
		session.inboundSeen[0] |= 1
		return true
	}
	distance := session.inboundSequence - sequence
	if distance >= replayWindowSize {
		return false
	}
	word := distance / 64
	bit := uint(distance % 64)
	mask := uint64(1) << bit
	if session.inboundSeen[word]&mask != 0 {
		return false
	}
	session.inboundSeen[word] |= mask
	return true
}

func shiftReplayWindow(window *[replayWindowWords]uint64, distance uint64) {
	if distance >= replayWindowSize {
		*window = [replayWindowWords]uint64{}
		return
	}
	wordShift := int(distance / 64)
	bitShift := uint(distance % 64)
	var shifted [replayWindowWords]uint64
	for destination := replayWindowWords - 1; destination >= 0; destination-- {
		source := destination - wordShift
		if source < 0 {
			continue
		}
		shifted[destination] |= window[source] << bitShift
		if bitShift > 0 && source > 0 {
			shifted[destination] |= window[source-1] >> (64 - bitShift)
		}
	}
	*window = shifted
}

func sequenceNonce(size int, sequence uint64) []byte {
	nonce := make([]byte, size)
	binary.BigEndian.PutUint64(nonce[size-8:], sequence)
	return nonce
}

func newSession(id protocol.RequestID, outboundKey, inboundKey [32]byte) (*Session, error) {
	outbound, err := newGCM(outboundKey)
	if err != nil {
		return nil, err
	}
	inbound, err := newGCM(inboundKey)
	if err != nil {
		return nil, err
	}
	return &Session{id: id, outbound: outbound, inbound: inbound}, nil
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func fixedSecret(sharedSecret []byte) ([32]byte, error) {
	var secret [32]byte
	if len(sharedSecret) != len(secret) {
		return secret, errors.New("shared secret must be exactly 32 bytes")
	}
	copy(secret[:], sharedSecret)
	return secret, nil
}

func clientAuthentication(secret [32]byte, id protocol.RequestID, publicKey, nonce [32]byte) [32]byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(clientAuthenticationLabel)
	mac.Write(id[:])
	mac.Write(publicKey[:])
	mac.Write(nonce[:])
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func handshakeTranscript(id protocol.RequestID, clientPublic, clientNonce, serverPublic, serverNonce [32]byte) [32]byte {
	hash := sha256.New()
	hash.Write(transcriptLabel)
	hash.Write(id[:])
	hash.Write(clientPublic[:])
	hash.Write(clientNonce[:])
	hash.Write(serverPublic[:])
	hash.Write(serverNonce[:])
	var transcript [32]byte
	copy(transcript[:], hash.Sum(nil))
	return transcript
}

func deriveDirectionalKeys(sharedKey []byte, secret, clientNonce, serverNonce, transcript [32]byte) ([32]byte, [32]byte) {
	saltMAC := hmac.New(sha256.New, secret[:])
	saltMAC.Write(hkdfSaltLabel)
	saltMAC.Write(clientNonce[:])
	saltMAC.Write(serverNonce[:])
	salt := saltMAC.Sum(nil)
	extract := hmac.New(sha256.New, salt)
	extract.Write(sharedKey)
	pseudorandomKey := extract.Sum(nil)
	info := append(append([]byte(nil), hkdfInfoLabel...), transcript[:]...)
	keyMaterial := hkdfExpand(pseudorandomKey, info, 64)
	var clientKey, serverKey [32]byte
	copy(clientKey[:], keyMaterial[:32])
	copy(serverKey[:], keyMaterial[32:64])
	return clientKey, serverKey
}

func hkdfExpand(pseudorandomKey, info []byte, length int) []byte {
	result := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(result) < length; counter++ {
		mac := hmac.New(sha256.New, pseudorandomKey)
		mac.Write(previous)
		mac.Write(info)
		mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		result = append(result, previous...)
	}
	return bytes.Clone(result[:length])
}
