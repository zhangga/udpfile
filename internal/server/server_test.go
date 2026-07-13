package server

import (
	"testing"
	"time"

	"udpfile/internal/protocol"
)

func TestCleanupExpiredReleasesAbandonedPreparation(t *testing.T) {
	id := protocol.RequestID{1, 2, 3}
	instance := &Server{
		config: Config{SessionTTL: time.Minute},
		sessions: map[protocol.RequestID]*session{
			id: {
				requestedPath: "slow-directory",
				lastAccess:    time.Now().Add(-2 * time.Minute),
				preparing:     true,
			},
		},
	}

	instance.cleanupExpired()
	if _, exists := instance.sessions[id]; exists {
		t.Fatal("cleanupExpired() retained an abandoned preparing session")
	}
}

func TestSentChunkWindowTracksUniqueOutOfOrderChunksWithBoundedMemory(t *testing.T) {
	current := &session{}
	for _, index := range []uint32{2, 0, 1} {
		if !markChunkSent(current, index) {
			t.Fatalf("markChunkSent(%d) = false, want first send", index)
		}
	}
	if current.sentWindowBase != 3 {
		t.Fatalf("sent window base = %d, want 3", current.sentWindowBase)
	}
	for _, index := range []uint32{0, 1, 2} {
		if markChunkSent(current, index) {
			t.Fatalf("markChunkSent(%d) counted a retransmission", index)
		}
	}
	if chunkWithinSendWindow(current, current.sentWindowBase+sendWindowSize) {
		t.Fatal("send window accepted a new chunk beyond its fixed bound")
	}
}
