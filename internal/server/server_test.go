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
