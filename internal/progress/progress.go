package progress

import (
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	maximumQuietInterval = 2 * time.Second
	percentageStep       = 5
)

type Reporter struct {
	mu              sync.Mutex
	logger          *log.Logger
	label           string
	totalBytes      uint64
	totalChunks     uint32
	completedBytes  uint64
	completedChunks uint32
	lastBucket      int
	lastReport      time.Time
	observer        func(Snapshot)
}

type Snapshot struct {
	Percent         int
	CompletedBytes  uint64
	TotalBytes      uint64
	CompletedChunks uint32
	TotalChunks     uint32
}

func New(logger *log.Logger, label string, totalBytes uint64, totalChunks uint32) *Reporter {
	return &Reporter{
		logger:      logger,
		label:       label,
		totalBytes:  totalBytes,
		totalChunks: totalChunks,
		lastBucket:  -1,
	}
}

func (reporter *Reporter) Observe(observer func(Snapshot)) {
	if reporter == nil {
		return
	}
	reporter.mu.Lock()
	reporter.observer = observer
	reporter.mu.Unlock()
}

func (reporter *Reporter) Report(completedBytes uint64, completedChunks uint32) {
	if reporter == nil {
		return
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if completedBytes > reporter.completedBytes {
		reporter.completedBytes = completedBytes
	}
	if completedChunks > reporter.completedChunks {
		reporter.completedChunks = completedChunks
	}
	if reporter.completedBytes > reporter.totalBytes {
		reporter.completedBytes = reporter.totalBytes
	}
	if reporter.completedChunks > reporter.totalChunks {
		reporter.completedChunks = reporter.totalChunks
	}
	percent := 100
	if reporter.totalBytes > 0 {
		percent = int(reporter.completedBytes * 100 / reporter.totalBytes)
	}
	snapshot := Snapshot{
		Percent:         percent,
		CompletedBytes:  reporter.completedBytes,
		TotalBytes:      reporter.totalBytes,
		CompletedChunks: reporter.completedChunks,
		TotalChunks:     reporter.totalChunks,
	}
	observer := reporter.observer
	now := time.Now()
	completed := reporter.completedBytes == reporter.totalBytes && reporter.completedChunks == reporter.totalChunks
	bucket := percent / percentageStep
	shouldLog := reporter.logger != nil
	if bucket == reporter.lastBucket {
		if completed || now.Sub(reporter.lastReport) < maximumQuietInterval {
			shouldLog = false
		}
	}
	if shouldLog {
		reporter.lastBucket = bucket
		reporter.lastReport = now
	}
	logger := reporter.logger
	label := reporter.label
	if observer != nil {
		observer(snapshot)
	}
	if shouldLog {
		logger.Printf("%s进度 %d%%（%s / %s，%d / %d 分片）",
			label,
			snapshot.Percent,
			formatBytes(snapshot.CompletedBytes),
			formatBytes(snapshot.TotalBytes),
			snapshot.CompletedChunks,
			snapshot.TotalChunks,
		)
	}
}

func formatBytes(value uint64) string {
	const (
		kib = uint64(1 << 10)
		mib = uint64(1 << 20)
		gib = uint64(1 << 30)
	)
	switch {
	case value >= gib:
		return fmt.Sprintf("%.2f GiB", float64(value)/float64(gib))
	case value >= mib:
		return fmt.Sprintf("%.2f MiB", float64(value)/float64(mib))
	case value >= kib:
		return fmt.Sprintf("%.2f KiB", float64(value)/float64(kib))
	default:
		return fmt.Sprintf("%d B", value)
	}
}
