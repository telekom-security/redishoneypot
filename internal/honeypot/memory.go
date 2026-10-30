package honeypot

import "sync/atomic"

const (
	defaultMaxDataBytes = 64 << 20
	// entryOverhead is what a key costs the honeypot beside its bytes: the
	// map slot, the string headers and the rounding of its allocations
	// (about 120 bytes for short keys in Go).
	entryOverhead = 128
	// redisEntryOverhead is what Redis spends per key; INFO reports it.
	redisEntryOverhead = 64
	// keyReplyOverhead is what one key of a KEYS or SCAN reply costs while
	// it is built and encoded, beside the key's bytes.
	keyReplyOverhead = 96
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

func keyReplyCost(key string) int64 {
	return int64(len(key) + keyReplyOverhead)
}

// shownDataBytes is the data INFO and the RDB header report: the budget with
// Redis' overhead per key instead of the honeypot's.
func (s *RedisServer) shownDataBytes() int64 {
	shown := s.budget.bytes() - s.store.KeyCount()*(entryOverhead-redisEntryOverhead)
	if shown < 0 {
		return 0
	}
	return shown
}
