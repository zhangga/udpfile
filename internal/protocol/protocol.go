package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	Version         = byte(1)
	MaxDatagramSize = 1232
	ChunkSize       = 1200
	headerSize      = 22
	maxRequestPath  = 1024
)

var magic = [4]byte{'U', 'D', 'F', '1'}

type Type byte

const (
	TypeRequest Type = iota + 1
	TypeMeta
	TypeGet
	TypeData
	TypeError
	TypeDone
)

type RequestID [16]byte

type Meta struct {
	Size      uint64
	Chunks    uint32
	ChunkSize uint16
	SHA256    [32]byte
}

func NewRequestID() (RequestID, error) {
	var id RequestID
	if _, err := rand.Read(id[:]); err != nil {
		return RequestID{}, fmt.Errorf("create request ID: %w", err)
	}
	return id, nil
}

func Header(datagram []byte) (Type, RequestID, error) {
	packetType, id, _, err := decode(datagram)
	return packetType, id, err
}

func EncodeRequest(id RequestID, requestedPath string) ([]byte, error) {
	if requestedPath == "" {
		return nil, errors.New("requested path is empty")
	}
	if !utf8.ValidString(requestedPath) {
		return nil, errors.New("requested path is not valid UTF-8")
	}
	if len(requestedPath) > maxRequestPath {
		return nil, fmt.Errorf("requested path is longer than %d bytes", maxRequestPath)
	}
	return encode(TypeRequest, id, []byte(requestedPath))
}

func DecodeRequest(datagram []byte) (RequestID, string, error) {
	id, payload, err := decodeType(datagram, TypeRequest)
	if err != nil {
		return RequestID{}, "", err
	}
	requestedPath := string(payload)
	if requestedPath == "" || len(payload) > maxRequestPath || !utf8.Valid(payload) {
		return RequestID{}, "", errors.New("invalid requested path")
	}
	return id, requestedPath, nil
}

func EncodeMeta(id RequestID, meta Meta) ([]byte, error) {
	payload := make([]byte, 46)
	binary.BigEndian.PutUint64(payload[0:8], meta.Size)
	binary.BigEndian.PutUint32(payload[8:12], meta.Chunks)
	binary.BigEndian.PutUint16(payload[12:14], meta.ChunkSize)
	copy(payload[14:46], meta.SHA256[:])
	return encode(TypeMeta, id, payload)
}

func DecodeMeta(datagram []byte) (RequestID, Meta, error) {
	id, payload, err := decodeType(datagram, TypeMeta)
	if err != nil {
		return RequestID{}, Meta{}, err
	}
	if len(payload) != 46 {
		return RequestID{}, Meta{}, errors.New("invalid metadata length")
	}
	meta := Meta{
		Size:      binary.BigEndian.Uint64(payload[0:8]),
		Chunks:    binary.BigEndian.Uint32(payload[8:12]),
		ChunkSize: binary.BigEndian.Uint16(payload[12:14]),
	}
	copy(meta.SHA256[:], payload[14:46])
	if meta.ChunkSize == 0 || int(meta.ChunkSize) > ChunkSize {
		return RequestID{}, Meta{}, errors.New("invalid metadata chunk size")
	}
	expectedChunks := uint64(0)
	if meta.Size > 0 {
		expectedChunks = (meta.Size + uint64(meta.ChunkSize) - 1) / uint64(meta.ChunkSize)
	}
	if expectedChunks != uint64(meta.Chunks) {
		return RequestID{}, Meta{}, errors.New("inconsistent metadata chunk count")
	}
	return id, meta, nil
}

func EncodeGet(id RequestID, index uint32) ([]byte, error) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, index)
	return encode(TypeGet, id, payload)
}

func DecodeGet(datagram []byte) (RequestID, uint32, error) {
	id, payload, err := decodeType(datagram, TypeGet)
	if err != nil {
		return RequestID{}, 0, err
	}
	if len(payload) != 4 {
		return RequestID{}, 0, errors.New("invalid chunk request length")
	}
	return id, binary.BigEndian.Uint32(payload), nil
}

func EncodeData(id RequestID, index uint32, data []byte) ([]byte, error) {
	if len(data) > ChunkSize {
		return nil, fmt.Errorf("chunk exceeds %d bytes", ChunkSize)
	}
	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload[0:4], index)
	copy(payload[4:], data)
	return encode(TypeData, id, payload)
}

func DecodeData(datagram []byte) (RequestID, uint32, []byte, error) {
	id, payload, err := decodeType(datagram, TypeData)
	if err != nil {
		return RequestID{}, 0, nil, err
	}
	if len(payload) < 4 || len(payload)-4 > ChunkSize {
		return RequestID{}, 0, nil, errors.New("invalid chunk data length")
	}
	return id, binary.BigEndian.Uint32(payload[0:4]), payload[4:], nil
}

func EncodeError(id RequestID, message string) ([]byte, error) {
	if message == "" {
		message = "unknown server error"
	}
	maxLength := MaxDatagramSize - headerSize
	if len(message) > maxLength {
		message = message[:maxLength]
	}
	return encode(TypeError, id, []byte(message))
}

func DecodeError(datagram []byte) (RequestID, string, error) {
	id, payload, err := decodeType(datagram, TypeError)
	if err != nil {
		return RequestID{}, "", err
	}
	return id, string(payload), nil
}

func EncodeDone(id RequestID) ([]byte, error) {
	return encode(TypeDone, id, nil)
}

func DecodeDone(datagram []byte) (RequestID, error) {
	id, payload, err := decodeType(datagram, TypeDone)
	if err != nil {
		return RequestID{}, err
	}
	if len(payload) != 0 {
		return RequestID{}, errors.New("invalid completion packet length")
	}
	return id, nil
}

func encode(packetType Type, id RequestID, payload []byte) ([]byte, error) {
	if headerSize+len(payload) > MaxDatagramSize {
		return nil, fmt.Errorf("datagram exceeds %d bytes", MaxDatagramSize)
	}
	datagram := make([]byte, headerSize+len(payload))
	copy(datagram[0:4], magic[:])
	datagram[4] = Version
	datagram[5] = byte(packetType)
	copy(datagram[6:22], id[:])
	copy(datagram[22:], payload)
	return datagram, nil
}

func decodeType(datagram []byte, want Type) (RequestID, []byte, error) {
	got, id, payload, err := decode(datagram)
	if err != nil {
		return RequestID{}, nil, err
	}
	if got != want {
		return RequestID{}, nil, fmt.Errorf("unexpected packet type %d", got)
	}
	return id, payload, nil
}

func decode(datagram []byte) (Type, RequestID, []byte, error) {
	if len(datagram) < headerSize || len(datagram) > MaxDatagramSize {
		return 0, RequestID{}, nil, errors.New("invalid datagram length")
	}
	if string(datagram[0:4]) != string(magic[:]) || datagram[4] != Version {
		return 0, RequestID{}, nil, errors.New("invalid protocol header")
	}
	packetType := Type(datagram[5])
	if packetType < TypeRequest || packetType > TypeDone {
		return 0, RequestID{}, nil, errors.New("unknown packet type")
	}
	var id RequestID
	copy(id[:], datagram[6:22])
	return packetType, id, datagram[22:], nil
}
