package honeypot

import (
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

// replicationState records SLAVEOF/REPLICAOF. The honeypot never connects to
// the named master; it reports the link as down, like a real replica whose
// master is unreachable. The state belongs to the source address that set it,
// so one attacker never sees the master another one named, and it is
// forgotten ReplicaStateTTL after that address last sent SLAVEOF.
type replicationState struct {
	masterHost string
	masterPort int
	since      time.Time
	touched    time.Time
}

// maxReplicaSources bounds the addresses with a replication state.
const maxReplicaSources = 4096

// maxMasterHostBytes caps the master host a replica state keeps.
const maxMasterHostBytes = 1024

func (s *RedisServer) replication(state *clientState) (replicationState, bool) {
	s.replMu.Lock()
	defer s.replMu.Unlock()
	repl, ok := s.replicas[state.remoteIP]
	if !ok {
		return replicationState{}, false
	}
	if time.Since(repl.touched) > s.options.ReplicaStateTTL {
		delete(s.replicas, state.remoteIP)
		return replicationState{}, false
	}
	return *repl, true
}

func (s *RedisServer) isReplica(state *clientState) bool {
	_, replica := s.replication(state)
	return replica
}

func (s *RedisServer) isReadOnlyReplica(state *clientState) bool {
	if !s.isReplica(state) {
		return false
	}
	setting := s.configValue("replica-read-only")
	if setting == "" {
		setting = s.configValue("slave-read-only")
	}
	return setting != "no"
}

func (s *RedisServer) handleReplicaOf(state *clientState, args []string) RESPValue {
	if strings.EqualFold(args[1], "no") && strings.EqualFold(args[2], "one") {
		s.replMu.Lock()
		delete(s.replicas, state.remoteIP)
		s.replMu.Unlock()
		return SimpleString("OK")
	}

	port, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil || port < 0 || port > 65535 {
		if s.profile.modernErrors() {
			return ErrorReply("ERR Invalid master port")
		}
		return notIntegerErr
	}

	host := truncateBytes(args[1], maxMasterHostBytes)
	now := time.Now()
	s.replMu.Lock()
	defer s.replMu.Unlock()
	if repl, ok := s.replicas[state.remoteIP]; ok && now.Sub(repl.touched) <= s.options.ReplicaStateTTL {
		repl.touched = now
		if strings.EqualFold(repl.masterHost, host) && repl.masterPort == int(port) {
			return SimpleString("OK Already connected to specified master")
		}
		*repl = replicationState{masterHost: host, masterPort: int(port), since: now, touched: now}
		return SimpleString("OK")
	}
	if len(s.replicas) >= maxReplicaSources {
		s.pruneReplicas(now)
	}
	s.replicas[state.remoteIP] = &replicationState{masterHost: host, masterPort: int(port), since: now, touched: now}
	return SimpleString("OK")
}

// pruneReplicas drops expired replica states and, when none expired, the one
// touched longest ago. The caller must hold s.replMu.
func (s *RedisServer) pruneReplicas(now time.Time) {
	oldestIP := ""
	var oldest time.Time
	for ip, repl := range s.replicas {
		if now.Sub(repl.touched) > s.options.ReplicaStateTTL {
			delete(s.replicas, ip)
			continue
		}
		if oldestIP == "" || repl.touched.Before(oldest) {
			oldestIP, oldest = ip, repl.touched
		}
	}
	if len(s.replicas) >= maxReplicaSources {
		delete(s.replicas, oldestIP)
	}
}

func (s *RedisServer) handleRole(state *clientState) RESPValue {
	if repl, replica := s.replication(state); replica {
		return Array(
			BulkString("slave"),
			BulkString(repl.masterHost),
			IntegerReply(int64(repl.masterPort)),
			BulkString("connect"),
			IntegerReply(-1),
		)
	}
	return Array(BulkString("master"), IntegerReply(0), Array())
}

// handleSync sends the keyspace as an RDB file. Its size counts against
// MaxReplyBytes while it is built and written; when it does not fit the
// connection is closed without a reply, like Redis' replica output limit.
func (s *RedisServer) handleSync(state *clientState, name string) commandResult {
	if s.isReplica(state) {
		return ok(ErrorReply("NOMASTERLINK Can't SYNC while not connected with my master"))
	}
	// The RDB and the reply that carries it are two copies of the data.
	reserve := 2 * (s.budget.bytes() + 4096)
	if !s.reserveReply(reserve) {
		return commandResult{reply: RawReply(""), silent: true, close: true, replyLimited: true}
	}
	s.syncFull.Add(1)
	state.replica = true
	rdb := s.buildRDB()
	payload := "$" + strconv.Itoa(len(rdb)) + "\r\n" + string(rdb)
	result := ok(RawReply(payload))
	if name != "sync" {
		result = ok(RawReply("+FULLRESYNC " + s.runtime.masterReplID + " 0\r\n" + payload))
	}
	result.reserved = reserve
	return result
}

// buildRDB serializes the keyspace as an RDB file of the persona's version,
// with the same auxiliary fields and CRC64 trailer a real master sends.
func (s *RedisServer) buildRDB() []byte {
	var out []byte
	out = append(out, "REDIS"...)
	out = append(out, []byte(padRDBVersion(s.profile.RDBVersion))...)

	aux := func(key string, value string) {
		out = append(out, 0xFA)
		out = appendRDBString(out, key)
		out = appendRDBString(out, value)
	}
	verKey := "redis-ver"
	if s.profile.isValkey() {
		verKey = "valkey-ver"
	}
	aux(verKey, s.profile.Version)
	aux("redis-bits", "64")
	aux("ctime", strconv.FormatInt(time.Now().Unix(), 10))
	usedMemory, _, _ := s.runtime.memory(s.shownDataBytes())
	aux("used-mem", strconv.FormatInt(usedMemory, 10))
	if s.profile.atLeast(4, 0) {
		aux("repl-stream-db", "0")
		aux("repl-id", s.runtime.masterReplID)
		aux("repl-offset", "0")
	}
	if s.profile.atLeast(7, 0) {
		aux("aof-base", "0")
	} else {
		aux("aof-preamble", "0")
	}

	for db, entries := range s.store.Snapshot() {
		if len(entries) == 0 {
			continue
		}
		expires := 0
		for _, entry := range entries {
			if !entry.expireAt.IsZero() {
				expires++
			}
		}
		out = append(out, 0xFE)
		out = appendRDBLength(out, uint64(db))
		out = append(out, 0xFB)
		out = appendRDBLength(out, uint64(len(entries)))
		out = appendRDBLength(out, uint64(expires))
		for _, entry := range entries {
			if !entry.expireAt.IsZero() {
				out = append(out, 0xFC)
				out = binary.LittleEndian.AppendUint64(out, uint64(entry.expireAt.UnixMilli()))
			}
			out = append(out, 0x00)
			out = appendRDBString(out, entry.key)
			out = appendRDBString(out, entry.value)
		}
	}

	// Before Redis 7 the master replicates cached Lua scripts as "lua" aux
	// fields after the keyspace.
	if !s.profile.atLeast(7, 0) {
		for _, body := range s.scripts.bodies() {
			aux("lua", body)
		}
	}

	out = append(out, 0xFF)
	return binary.LittleEndian.AppendUint64(out, crc64Jones(out))
}

func padRDBVersion(version int) string {
	text := strconv.Itoa(version)
	return strings.Repeat("0", 4-len(text)) + text
}

func appendRDBLength(out []byte, n uint64) []byte {
	switch {
	case n < 1<<6:
		return append(out, byte(n))
	case n < 1<<14:
		return append(out, byte(0x40|n>>8), byte(n))
	case n <= 0xFFFFFFFF:
		out = append(out, 0x80)
		return binary.BigEndian.AppendUint32(out, uint32(n))
	default:
		out = append(out, 0x81)
		return binary.BigEndian.AppendUint64(out, n)
	}
}

// appendRDBString uses Redis' integer encodings for numeric strings, like
// rdbSaveRawString's rdbTryIntegerEncoding.
func appendRDBString(out []byte, value string) []byte {
	if n, err := strconv.ParseInt(value, 10, 64); err == nil && strconv.FormatInt(n, 10) == value {
		switch {
		case n >= -(1<<7) && n <= 1<<7-1:
			return append(out, 0xC0, byte(int8(n)))
		case n >= -(1<<15) && n <= 1<<15-1:
			return binary.LittleEndian.AppendUint16(append(out, 0xC1), uint16(int16(n)))
		case n >= -(1<<31) && n <= 1<<31-1:
			return binary.LittleEndian.AppendUint32(append(out, 0xC2), uint32(int32(n)))
		}
	}
	out = appendRDBLength(out, uint64(len(value)))
	return append(out, value...)
}

var crc64JonesTable = func() [256]uint64 {
	// Reflected Jones polynomial as used by Redis' crc64.c.
	const poly = 0x95AC9329AC4BC9B5
	var table [256]uint64
	for i := range table {
		crc := uint64(i)
		for j := 0; j < 8; j++ {
			if crc&1 == 1 {
				crc = crc>>1 ^ poly
			} else {
				crc >>= 1
			}
		}
		table[i] = crc
	}
	return table
}()

func crc64Jones(data []byte) uint64 {
	var crc uint64
	for _, b := range data {
		crc = crc64JonesTable[byte(crc)^b] ^ crc>>8
	}
	return crc
}
