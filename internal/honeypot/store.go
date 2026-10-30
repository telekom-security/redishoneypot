package honeypot

import (
	"sort"
	"sync"
	"time"
)

type storeEntry struct {
	value    string
	expireAt time.Time
}

func (e storeEntry) expired(now time.Time) bool {
	return !e.expireAt.IsZero() && !now.Before(e.expireAt)
}

// Store is the in-memory string keyspace. Expired keys are removed lazily on
// access, like Redis' passive expiry, and by a bounded sweep of the keys with
// a TTL whenever the keyspace is counted. It keeps its counts and its bytes
// up to date, so INFO and DBSIZE never walk every key.
type Store struct {
	mu          sync.Mutex
	dbs         map[int]map[string]storeEntry
	stats       map[int]*keyspaceStats
	volatile    map[int]map[string]struct{}
	budget      *memBudget
	expiredKeys uint64
}

type keyspaceStats struct {
	keys    int
	expires int
}

// maxExpireSweep bounds the keys with a TTL one Keyspace call looks at.
const maxExpireSweep = 4096

func NewStore() *Store {
	return newStoreWithBudget(nil)
}

func newStoreWithBudget(budget *memBudget) *Store {
	return &Store{
		dbs:      make(map[int]map[string]storeEntry),
		stats:    make(map[int]*keyspaceStats),
		volatile: make(map[int]map[string]struct{}),
		budget:   budget,
	}
}

// lookup returns the live entry for key, deleting it when it has expired.
// The caller must hold s.mu.
func (s *Store) lookup(db int, key string, now time.Time) (storeEntry, bool) {
	values := s.dbs[db]
	if values == nil {
		return storeEntry{}, false
	}
	entry, ok := values[key]
	if !ok {
		return storeEntry{}, false
	}
	if entry.expired(now) {
		s.remove(db, key, entry)
		s.expiredKeys++
		return storeEntry{}, false
	}
	return entry, true
}

// put stores entry in place of old (exists tells whether there was one) and
// keeps the counts. The caller must hold s.mu and has reserved the bytes.
func (s *Store) put(db int, key string, entry storeEntry, old storeEntry, exists bool) {
	stats := s.stats[db]
	if stats == nil {
		stats = &keyspaceStats{}
		s.stats[db] = stats
	}
	if !exists {
		stats.keys++
	} else if !old.expireAt.IsZero() {
		stats.expires--
		delete(s.volatile[db], key)
	}
	if !entry.expireAt.IsZero() {
		stats.expires++
		volatile := s.volatile[db]
		if volatile == nil {
			volatile = make(map[string]struct{})
			s.volatile[db] = volatile
		}
		volatile[key] = struct{}{}
	}
	s.db(db)[key] = entry
}

// remove deletes key and gives its bytes back. The caller must hold s.mu.
func (s *Store) remove(db int, key string, entry storeEntry) {
	delete(s.dbs[db], key)
	if len(s.dbs[db]) == 0 {
		delete(s.dbs, db)
	}
	if stats := s.stats[db]; stats != nil {
		stats.keys--
		if !entry.expireAt.IsZero() {
			stats.expires--
		}
		if stats.keys <= 0 {
			delete(s.stats, db)
		}
	}
	if !entry.expireAt.IsZero() {
		delete(s.volatile[db], key)
		if len(s.volatile[db]) == 0 {
			delete(s.volatile, db)
		}
	}
	s.budget.release(entrySize(key, entry.value))
}

// Set stores value. A zero expireAt removes any TTL unless keepTTL is set.
func (s *Store) Set(db int, key string, value string) bool {
	return s.SetWithExpiry(db, key, value, time.Time{}, false)
}

// SetWithExpiry stores value; it reports false, and keeps the old value, when
// the new one does not fit into the data budget.
func (s *Store) SetWithExpiry(db int, key string, value string, expireAt time.Time, keepTTL bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.lookup(db, key, time.Now())
	if keepTTL && exists {
		expireAt = old.expireAt
	}
	delta := entrySize(key, value)
	if exists {
		delta -= entrySize(key, old.value)
	}
	if !s.budget.reserve(delta) {
		return false
	}
	s.put(db, key, storeEntry{value: value, expireAt: expireAt}, old, exists)
	return true
}

func (s *Store) Get(db int, key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.lookup(db, key, time.Now())
	return entry.value, ok
}

// TTL returns the remaining lifetime in milliseconds; hasTTL is false for
// persistent keys. Milliseconds, not a Duration: a TTL may exceed 292 years.
func (s *Store) TTL(db int, key string) (remainingMs int64, exists bool, hasTTL bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	entry, ok := s.lookup(db, key, now)
	if !ok {
		return 0, false, false
	}
	if entry.expireAt.IsZero() {
		return 0, true, false
	}
	return entry.expireAt.UnixMilli() - now.UnixMilli(), true, true
}

// Expire sets an absolute expiry; it reports whether the key existed.
func (s *Store) Expire(db int, key string, expireAt time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	entry, ok := s.lookup(db, key, now)
	if !ok {
		return false
	}
	if !expireAt.After(now) {
		s.remove(db, key, entry)
		return true
	}
	updated := entry
	updated.expireAt = expireAt
	s.put(db, key, updated, entry, true)
	return true
}

func (s *Store) Persist(db int, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.lookup(db, key, time.Now())
	if !ok || entry.expireAt.IsZero() {
		return false
	}
	updated := entry
	updated.expireAt = time.Time{}
	s.put(db, key, updated, entry, true)
	return true
}

func (s *Store) Exists(db int, keys []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	count := 0
	for _, key := range keys {
		if _, ok := s.lookup(db, key, now); ok {
			count++
		}
	}
	return count
}

func (s *Store) Del(db int, keys []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	count := 0
	for _, key := range keys {
		if entry, ok := s.lookup(db, key, now); ok {
			s.remove(db, key, entry)
			count++
		}
	}
	return count
}

func (s *Store) Keys(db int, pattern string) []string {
	keys, _ := s.KeysWithin(db, pattern, nil)
	return keys
}

// KeysWithin returns the live keys of db that match pattern, sorted. It first
// hands fit what their reply costs (keyReplyCost each) and builds nothing
// when fit refuses; a nil fit takes any cost.
func (s *Store) KeysWithin(db int, pattern string, fit func(cost int64) bool) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := s.dbs[db]
	if values == nil {
		return nil, fit == nil || fit(0)
	}

	now := time.Now()
	allKeys := pattern == "*"
	count := 0
	var cost int64
	for key := range values {
		if _, ok := s.lookup(db, key, now); !ok {
			continue
		}
		if allKeys || stringMatch(pattern, key, false) {
			count++
			cost += keyReplyCost(key)
		}
	}
	if fit != nil && !fit(cost) {
		return nil, false
	}
	keys := make([]string, 0, count)
	for key := range values {
		if allKeys || stringMatch(pattern, key, false) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, true
}

// KeyCount returns the keys of all databases, expired ones not yet removed
// included.
func (s *Store) KeyCount() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for _, stats := range s.stats {
		count += int64(stats.keys)
	}
	return count
}

// SizeHistogram counts the live string values of each database per power of
// two of their length (0 for empty values), without copying the keyspace.
func (s *Store) SizeHistogram() map[int]map[int64]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make(map[int]map[int64]int, len(s.dbs))
	for db, values := range s.dbs {
		buckets := map[int64]int{}
		for _, entry := range values {
			if entry.expired(now) {
				continue
			}
			buckets[powerOfTwoBucket(int64(len(entry.value)))]++
		}
		if len(buckets) > 0 {
			out[db] = buckets
		}
	}
	return out
}

func powerOfTwoBucket(size int64) int64 {
	if size <= 0 {
		return 0
	}
	bucket := int64(1)
	for bucket*2 <= size {
		bucket *= 2
	}
	return bucket
}

func (s *Store) Size(db int) int {
	return s.Keyspace()[db].keys
}

func (s *Store) FlushDB(db int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.dbs[db])
	var bytes int64
	for key, entry := range s.dbs[db] {
		bytes += entrySize(key, entry.value)
	}
	delete(s.dbs, db)
	delete(s.stats, db)
	delete(s.volatile, db)
	s.budget.release(bytes)
	return count
}

func (s *Store) FlushAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	var bytes int64
	for _, values := range s.dbs {
		count += len(values)
		for key, entry := range values {
			bytes += entrySize(key, entry.value)
		}
	}
	s.dbs = make(map[int]map[string]storeEntry)
	s.stats = make(map[int]*keyspaceStats)
	s.volatile = make(map[int]map[string]struct{})
	s.budget.release(bytes)
	return count
}

// Keyspace returns key and expiry counts per non-empty database. Like Redis'
// active expiry it first removes expired keys among a bounded sample of the
// keys with a TTL, so keys that expired may still be counted for a while.
func (s *Store) Keyspace() map[int]keyspaceStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	budget := maxExpireSweep
	for db, keys := range s.volatile {
		for key := range keys {
			if budget == 0 {
				break
			}
			budget--
			if entry, ok := s.dbs[db][key]; ok && entry.expired(now) {
				s.remove(db, key, entry)
				s.expiredKeys++
			}
		}
	}
	keyspace := make(map[int]keyspaceStats, len(s.stats))
	for db, stats := range s.stats {
		if stats.keys > 0 {
			keyspace[db] = *stats
		}
	}
	return keyspace
}

// ExpiredKeys returns how many keys expired so far.
func (s *Store) ExpiredKeys() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiredKeys
}

type snapshotEntry struct {
	key      string
	value    string
	expireAt time.Time
}

// Snapshot returns live entries per database, sorted by key.
func (s *Store) Snapshot() map[int][]snapshotEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make(map[int][]snapshotEntry)
	for db, values := range s.dbs {
		for key, entry := range values {
			if entry.expired(now) {
				continue
			}
			out[db] = append(out[db], snapshotEntry{key: key, value: entry.value, expireAt: entry.expireAt})
		}
		sort.Slice(out[db], func(i, j int) bool { return out[db][i].key < out[db][j].key })
	}
	return out
}

func (s *Store) db(db int) map[string]storeEntry {
	values := s.dbs[db]
	if values == nil {
		values = make(map[string]storeEntry)
		s.dbs[db] = values
	}
	return values
}
