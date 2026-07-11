package protocol

import (
	"bytes"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	id := RequestID{1, 2, 3, 4}
	packet, err := EncodeRequest(id, "photos/旅行")
	if err != nil {
		t.Fatalf("EncodeRequest() error = %v", err)
	}
	gotID, gotPath, err := DecodeRequest(packet)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}
	if gotID != id || gotPath != "photos/旅行" {
		t.Fatalf("decoded request = (%v, %q), want (%v, %q)", gotID, gotPath, id, "photos/旅行")
	}
}

func TestMetaAndDataRoundTrip(t *testing.T) {
	id := RequestID{9, 8, 7}
	wantMeta := Meta{Size: 3210, Chunks: 3, ChunkSize: 1120, SHA256: [32]byte{1, 3, 5, 7}}
	metaPacket, err := EncodeMeta(id, wantMeta)
	if err != nil {
		t.Fatalf("EncodeMeta() error = %v", err)
	}
	gotID, gotMeta, err := DecodeMeta(metaPacket)
	if err != nil {
		t.Fatalf("DecodeMeta() error = %v", err)
	}
	if gotID != id || gotMeta != wantMeta {
		t.Fatalf("decoded meta = (%v, %+v), want (%v, %+v)", gotID, gotMeta, id, wantMeta)
	}

	wantData := []byte{0, 1, 2, 3, 255}
	dataPacket, err := EncodeData(id, 2, wantData)
	if err != nil {
		t.Fatalf("EncodeData() error = %v", err)
	}
	gotID, gotIndex, gotData, err := DecodeData(dataPacket)
	if err != nil {
		t.Fatalf("DecodeData() error = %v", err)
	}
	if gotID != id || gotIndex != 2 || !bytes.Equal(gotData, wantData) {
		t.Fatalf("decoded data = (%v, %d, %v), want (%v, 2, %v)", gotID, gotIndex, gotData, id, wantData)
	}
}

func TestDecodeRejectsMalformedDatagram(t *testing.T) {
	if _, _, err := DecodeRequest([]byte("not udpfile")); err == nil {
		t.Fatal("DecodeRequest() accepted a malformed datagram")
	}
}

func TestDoneRoundTrip(t *testing.T) {
	id := RequestID{4, 3, 2, 1}
	packet, err := EncodeDone(id)
	if err != nil {
		t.Fatalf("EncodeDone() error = %v", err)
	}
	gotID, err := DecodeDone(packet)
	if err != nil {
		t.Fatalf("DecodeDone() error = %v", err)
	}
	if gotID != id {
		t.Fatalf("DecodeDone() ID = %v, want %v", gotID, id)
	}
}
