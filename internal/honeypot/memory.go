package honeypot

import "sync/atomic"

const (
	defaultMaxDataBytes = 64 << 20
	// entryOverhead approximates what Redis spends per key beside its bytes.
	entryOverhead = 64
	// maxScriptCacheBytes caps the script cache within the data budget.
	maxScriptCacheBytes = 8 << 20
)

// memBudget counts the bytes attackers can make the honeypot keep: keys,
// cached scripts and config values. Reservations above the limit fail.
type memBudget struct {
	used  atomic.Int64
	limit int64
}

func newMemBudget(limit int64) *memBudget {
	return &memBudget{limit: limit}
}

// reserve adds delta when the result stays within the limit; a release
// (delta <= 0) always succeeds. A nil budget is unlimited.
func (b *memBudget) reserve(delta int64) bool {
	if b == nil {
		return true
	}
	for {
		used := b.used.Load()
		next := used + delta
		if delta > 0 && b.limit > 0 && next > b.limit {
			return false
		}
		if next < 0 {
			next = 0
		}
		if b.used.CompareAndSwap(used, next) {
			return true
		}
	}
}

func (b *memBudget) release(delta int64) {
	if b != nil && delta > 0 {
		b.reserve(-delta)
	}
}

func (b *memBudget) bytes() int64 {
	if b == nil {
		return 0
	}
	return b.used.Load()
}

func entrySize(key, value string) int64 {
	return int64(len(key) + len(value) + entryOverhead)
}
