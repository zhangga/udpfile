package progress

import "testing"

func TestObserverReceivesEveryProgressAdvanceWithoutLogger(t *testing.T) {
	var snapshots []Snapshot
	reporter := New(nil, "接收", 20, 2)
	reporter.Observe(func(snapshot Snapshot) {
		snapshots = append(snapshots, snapshot)
	})

	reporter.Report(0, 0)
	reporter.Report(10, 1)
	reporter.Report(20, 2)

	if len(snapshots) != 3 {
		t.Fatalf("observer calls = %d, want 3", len(snapshots))
	}
	completed := snapshots[len(snapshots)-1]
	if completed.Percent != 100 || completed.CompletedBytes != 20 || completed.CompletedChunks != 2 {
		t.Fatalf("completed snapshot = %+v", completed)
	}
}
