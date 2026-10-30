package honeypot

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type runtimeFingerprint struct {
	redisBuildID string
	processID    int
	runID        string
	masterReplID string

	os                string
	monotonicClock    string
	totalSystemMemory int64

	usedMemory     atomic.Int64
	usedMemoryRSS  atomic.Int64
	usedMemoryPeak atomic.Int64
	usedMemoryLua  int64
	fragmentation  float64
	lruClockOffset int64

	clientRecentMaxInputBuffer  int64
	clientRecentMaxOutputBuffer int64
	latestForkUsec              int64

	cpuSysBase          float64
	cpuUserBase         float64
	cpuSysChildrenBase  float64
	cpuUserChildrenBase float64

	rdbLastSaveTime      atomic.Int64
	rdbLastBgsaveTimeSec atomic.Int64
	rdbChangesSinceSave  atomic.Int64
	rdbSaves             atomic.Int64
}

func pickString(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}
	return candidates[randomInt64(0, int64(len(candidates)-1))]
}

func newRuntimeFingerprint(profile RedisProfile) *runtimeFingerprint {
	usedMemory := randomInt64(950_000, 3_200_000)
	if profile.atLeast(8, 0) {
		usedMemory = randomInt64(1_900_000, 5_500_000)
	}

	peak := usedMemory + randomInt64(0, usedMemory/3)
	fragmentation := randomFloat64(1.65, 3.80)
	rss := int64(float64(usedMemory) * fragmentation)
	usedMemoryLua := randomInt64(34*1024, 56*1024)
	now := time.Now().Unix()

	processID := int(randomInt64(300, 65000))
	if profile.Containerized {
		processID = 1
	}
	totalMemory := int64(16_766_849_024)
	if len(profile.TotalMemoryCandidates) > 0 {
		totalMemory = profile.TotalMemoryCandidates[randomInt64(0, int64(len(profile.TotalMemoryCandidates)-1))]
	}

	fp := &runtimeFingerprint{
		redisBuildID: randomHex(16),
		processID:    processID,
		runID:        randomHex(40),
		masterReplID: randomHex(40),

		os:                pickString(profile.OSCandidates),
		monotonicClock:    pickString(profile.MonotonicCandidates),
		totalSystemMemory: totalMemory,

		usedMemoryLua:  usedMemoryLua,
		fragmentation:  fragmentation,
		lruClockOffset: randomInt64(0, 1<<24),

		clientRecentMaxInputBuffer:  randomInt64(2, 128),
		clientRecentMaxOutputBuffer: randomInt64(0, 16),
		latestForkUsec:              randomInt64(120, 2600),

		cpuSysBase:          randomFloat64(0.010, 0.450),
		cpuUserBase:         randomFloat64(0.010, 0.600),
		cpuSysChildrenBase:  randomFloat64(0.000, 0.035),
		cpuUserChildrenBase: randomFloat64(0.000, 0.045),
	}
	fp.usedMemory.Store(usedMemory)
	fp.usedMemoryRSS.Store(rss)
	fp.usedMemoryPeak.Store(peak)
	fp.rdbLastSaveTime.Store(now - randomInt64(30, 3600))
	fp.rdbLastBgsaveTimeSec.Store(randomInt64(-1, 3))
	return fp
}

func (f *runtimeFingerprint) markDirty(changes int64) {
	if changes <= 0 {
		return
	}
	f.rdbChangesSinceSave.Add(changes)
}

func (f *runtimeFingerprint) markSaved() {
	f.rdbSaves.Add(1)
	f.rdbChangesSinceSave.Store(0)
	f.rdbLastSaveTime.Store(time.Now().Unix())
	f.rdbLastBgsaveTimeSec.Store(randomInt64(0, 2))
}

// memory returns used_memory, used_memory_rss and used_memory_peak for the
// bytes the data set holds now: the idle base of the persona plus the data,
// so INFO grows and shrinks with what clients store.
func (f *runtimeFingerprint) memory(dataBytes int64) (used, rss, peak int64) {
	base := f.usedMemory.Load()
	used = base + dataBytes
	rss = f.usedMemoryRSS.Load() + dataBytes + dataBytes/10
	for {
		peak = f.usedMemoryPeak.Load()
		if used <= peak || f.usedMemoryPeak.CompareAndSwap(peak, used) {
			break
		}
	}
	if peak < used {
		peak = used
	}
	return used, rss, peak
}

func (f *runtimeFingerprint) lruClock(uptimeSeconds int64) int64 {
	return (f.lruClockOffset + uptimeSeconds) % (1 << 24)
}

func (f *runtimeFingerprint) cpuSys(uptimeSeconds int64) float64 {
	return f.cpuSysBase + float64(uptimeSeconds)*0.0017
}

func (f *runtimeFingerprint) cpuUser(uptimeSeconds int64) float64 {
	return f.cpuUserBase + float64(uptimeSeconds)*0.0021
}

func formatRedisBytes(bytes int64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
	)
	switch {
	case bytes >= 1024*gib:
		return fmt.Sprintf("%.2fT", float64(bytes)/(1024*gib))
	case bytes >= gib:
		return fmt.Sprintf("%.2fG", float64(bytes)/gib)
	case bytes >= mib:
		return fmt.Sprintf("%.2fM", float64(bytes)/mib)
	case bytes >= kib:
		return fmt.Sprintf("%.2fK", float64(bytes)/kib)
	default:
		return strconv.FormatInt(bytes, 10) + "B"
	}
}

func randomHex(bytesLen int) string {
	buf := make([]byte, bytesLen/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", bytesLen)
	}
	return hex.EncodeToString(buf)
}

func randomInt64(min int64, max int64) int64 {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return min
	}
	return min + n.Int64()
}

func randomFloat64(min float64, max float64) float64 {
	if max <= min {
		return min
	}
	n := randomInt64(0, 1_000_000)
	return min + (float64(n)/1_000_000)*(max-min)
}
