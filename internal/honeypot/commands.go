package honeypot

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type commandResult struct {
	reply RESPValue
	close bool
	// silent closes the connection without any reply, like Redis does for
	// cross-protocol (HTTP) requests.
	silent bool
	// noReply suppresses the reply (REPLCONF ACK from a replica).
	noReply bool
	// rejected marks commands refused before execution (arity, unknown
	// subcommand); they count as rejected_calls in commandstats.
	rejected bool
	statName string
	// reserved is the reply size the command already counted against
	// MaxReplyBytes (SYNC, KEYS, SCAN); handleConn releases it after the write.
	reserved int64
	// replyLimited marks a reply dropped for MaxReplyBytes.
	replyLimited bool
}

// emulatedCommands are executed by the honeypot. Commands the persona knows
// but that are not listed here answer like an unknown command.
var emulatedCommands = map[string]bool{
	"auth": true, "bgsave": true, "client": true, "command": true, "config": true,
	"dbsize": true, "debug": true, "del": true, "echo": true, "exists": true,
	"expire": true, "flushall": true, "flushdb": true, "get": true, "hello": true,
	"info": true, "keys": true, "lastsave": true, "mget": true, "module": true,
	"persist": true, "pexpire": true, "ping": true, "psync": true, "pttl": true,
	"quit": true, "replconf": true, "replicaof": true, "role": true, "save": true,
	"scan": true, "select": true, "set": true, "slaveof": true, "sync": true,
	"time": true, "ttl": true, "type": true,
	"eval": true, "eval_ro": true, "evalsha": true, "evalsha_ro": true,
	"script": true, "function": true, "fcall": true, "fcall_ro": true,
}

func ok(reply RESPValue) commandResult {
	return commandResult{reply: reply}
}

func rejected(reply RESPValue) commandResult {
	return commandResult{reply: reply, rejected: true}
}

func errorf(format string, args ...any) RESPValue {
	return ErrorReply(fmt.Sprintf(format, args...))
}

var (
	syntaxError    = ErrorReply("ERR syntax error")
	notIntegerErr  = ErrorReply("ERR value is not an integer or out of range")
	readonlyErr    = ErrorReply("READONLY You can't write against a read only replica.")
	wrongPassReply = ErrorReply("WRONGPASS invalid username-password pair or user is disabled.")
)

func (s *RedisServer) handleCommand(state *clientState, args []string) commandResult {
	name := strings.ToLower(args[0])

	// Redis treats these as cross-protocol scripting attempts and closes the
	// connection silently (securityWarningCommand).
	if name == "post" || name == "host:" {
		return commandResult{reply: RawReply(""), silent: true, close: true}
	}

	// Before Redis 7 QUIT is handled ahead of the command table lookup.
	if name == "quit" {
		return commandResult{reply: SimpleString("OK"), close: true, statName: s.statNameFor("quit")}
	}

	entry, known := s.profile.data.commands[name]
	if !known || !emulatedCommands[name] {
		return rejected(s.unknownCommand(args))
	}
	if !arityOK(entry.arity, len(args)) {
		result := rejected(wrongArity(name))
		result.statName = s.rejectedStatName(name)
		return result
	}

	statName := name
	if len(entry.subcommands) > 0 && len(args) >= 2 {
		sub := name + "|" + strings.ToLower(args[1])
		subEntry, found := entry.subcommands[sub]
		if !found {
			return rejected(errorf("ERR unknown subcommand '%s'. Try %s HELP.", truncateBytes(args[1], 128), strings.ToUpper(name)))
		}
		if !arityOK(subEntry.arity, len(args)) {
			result := rejected(wrongArity(sub))
			result.statName = s.rejectedStatName(sub)
			return result
		}
		statName = sub
	}

	if entry.flags["write"] && s.isReadOnlyReplica(state) {
		result := ok(readonlyErr)
		result.statName = statName
		return result
	}

	result := s.execute(state, name, args)
	if result.statName == "" {
		result.statName = statName
	}
	return result
}

// arityOK applies Redis' check: positive arity is exact, negative is a
// minimum, and 0 (Redis 5's COMMAND) accepts anything.
func arityOK(arity int64, argc int) bool {
	if arity > 0 {
		return int64(argc) == arity
	}
	return int64(argc) >= -arity
}

// rejectedStatName returns where a rejected call is counted; rejected_calls
// exist in commandstats since Redis 6.2.
func (s *RedisServer) rejectedStatName(name string) string {
	if s.profile.atLeast(6, 2) {
		return name
	}
	return ""
}

func (s *RedisServer) statNameFor(name string) string {
	if _, known := s.profile.data.commands[name]; known {
		return name
	}
	return ""
}

func (s *RedisServer) execute(state *clientState, name string, args []string) commandResult {
	switch name {
	case "ping":
		if len(args) == 1 {
			return ok(SimpleString("PONG"))
		}
		if len(args) == 2 {
			return ok(BulkString(args[1]))
		}
		return ok(wrongArity(name))
	case "echo":
		return ok(BulkString(args[1]))
	case "auth":
		return ok(s.handleAuth(args))
	case "hello":
		return ok(s.handleHello(state, args))
	case "info":
		return ok(s.handleInfo(state, args[1:]))
	case "set":
		return ok(s.handleSet(state, args))
	case "get":
		return ok(s.lookupString(state, args[1]))
	case "mget":
		items := make([]RESPValue, 0, len(args)-1)
		for _, key := range args[1:] {
			items = append(items, s.lookupString(state, key))
		}
		return ok(Array(items...))
	case "del":
		deleted := s.store.Del(state.db, args[1:])
		s.runtime.markDirty(int64(deleted))
		return ok(IntegerReply(int64(deleted)))
	case "exists":
		return ok(IntegerReply(int64(s.store.Exists(state.db, args[1:]))))
	case "keys":
		return s.keysResult(state.db, args[1], nil)
	case "scan":
		return s.handleScan(state, args)
	case "type":
		if _, exists := s.store.Get(state.db, args[1]); exists {
			return ok(SimpleString("string"))
		}
		return ok(SimpleString("none"))
	case "ttl", "pttl":
		remaining, exists, hasTTL := s.store.TTL(state.db, args[1])
		switch {
		case !exists:
			return ok(IntegerReply(-2))
		case !hasTTL:
			return ok(IntegerReply(-1))
		case name == "pttl":
			return ok(IntegerReply(remaining))
		default:
			return ok(IntegerReply((remaining + 500) / 1000))
		}
	case "expire", "pexpire":
		return ok(s.handleExpire(state, name, args))
	case "persist":
		if s.store.Persist(state.db, args[1]) {
			return ok(IntegerReply(1))
		}
		return ok(IntegerReply(0))
	case "flushall", "flushdb":
		if len(args) > 2 || (len(args) == 2 && !strings.EqualFold(args[1], "async") && !strings.EqualFold(args[1], "sync")) {
			return ok(syntaxError)
		}
		var flushed int
		if name == "flushall" {
			flushed = s.store.FlushAll()
		} else {
			flushed = s.store.FlushDB(state.db)
		}
		s.runtime.markDirty(int64(flushed))
		return ok(SimpleString("OK"))
	case "save":
		s.runtime.markSaved()
		return ok(SimpleString("OK"))
	case "bgsave":
		if len(args) == 2 && !strings.EqualFold(args[1], "schedule") {
			return ok(syntaxError)
		}
		s.runtime.markSaved()
		return ok(SimpleString("Background saving started"))
	case "lastsave":
		return ok(IntegerReply(s.runtime.rdbLastSaveTime.Load()))
	case "select":
		db, err := strconv.Atoi(args[1])
		if err != nil {
			return ok(notIntegerErr)
		}
		databases, _ := strconv.Atoi(s.configValue("databases"))
		if databases <= 0 {
			databases = 16
		}
		if db < 0 || db >= databases {
			return ok(ErrorReply("ERR DB index is out of range"))
		}
		state.db = db
		return ok(SimpleString("OK"))
	case "dbsize":
		return ok(IntegerReply(int64(s.store.Size(state.db))))
	case "config":
		return ok(s.handleConfig(state, args))
	case "client":
		return ok(s.handleClient(state, args))
	case "command":
		return ok(s.handleCommandCommand(args))
	case "module":
		return ok(s.handleModule(state, args))
	case "debug":
		return ok(s.handleDebug(state, args))
	case "role":
		return ok(s.handleRole(state))
	case "time":
		now := time.Now()
		return ok(Array(
			BulkString(strconv.FormatInt(now.Unix(), 10)),
			BulkString(strconv.FormatInt(int64(now.Nanosecond()/1000), 10)),
		))
	case "slaveof", "replicaof":
		return ok(s.handleReplicaOf(state, args))
	case "replconf":
		if strings.EqualFold(args[1], "ack") || strings.EqualFold(args[1], "fack") {
			return commandResult{noReply: true}
		}
		return ok(SimpleString("OK"))
	case "psync", "sync":
		return s.handleSync(state, name)
	case "eval", "eval_ro", "evalsha", "evalsha_ro":
		return ok(s.handleEval(name, args))
	case "script":
		return ok(s.handleScript(args))
	case "function":
		return ok(s.handleFunction(args))
	case "fcall", "fcall_ro":
		if reply := checkNumKeys(args); reply.kind == respError {
			return ok(reply)
		}
		return ok(ErrorReply("ERR Function not found"))
	default:
		return rejected(s.unknownCommand(args))
	}
}

func (s *RedisServer) lookupString(state *clientState, key string) RESPValue {
	value, exists := s.store.Get(state.db, key)
	if exists {
		s.keyspaceHits.Add(1)
		return BulkString(value)
	}
	s.keyspaceMisses.Add(1)
	return NilBulkString()
}

func wrongArity(command string) RESPValue {
	return ErrorReply("ERR wrong number of arguments for '" + strings.ToLower(command) + "' command")
}

// truncateBytes mirrors printf's "%.Ns" on C strings (bytes, not runes).
func truncateBytes(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func (s *RedisServer) unknownCommand(args []string) RESPValue {
	var preview strings.Builder
	if !s.profile.modernErrors() {
		for i := 1; i < len(args) && preview.Len() < 128; i++ {
			fmt.Fprintf(&preview, "`%s`, ", truncateBytes(args[i], 128-preview.Len()))
		}
		return errorf("ERR unknown command `%s`, with args beginning with: %s", args[0], preview.String())
	}
	if len(args) == 1 && !s.profile.isValkey() && s.profile.atLeast(8, 0) {
		return errorf("ERR unknown command '%s'", truncateBytes(args[0], 128))
	}
	for i := 1; i < len(args) && preview.Len() < 128; i++ {
		fmt.Fprintf(&preview, "'%s' ", truncateBytes(args[i], 128-preview.Len()))
	}
	return errorf("ERR unknown command '%s', with args beginning with: %s", truncateBytes(args[0], 128), preview.String())
}

// legacySubcommandError is the pre-7.0 reply for unknown subcommands and for
// subcommands with the wrong number of arguments.
func (s *RedisServer) legacySubcommandError(sub string, command string) RESPValue {
	dot := "."
	if command == "CLIENT" && !s.profile.atLeast(6, 0) {
		dot = ""
	}
	return errorf("ERR Unknown subcommand or wrong number of arguments for '%s'. Try %s HELP%s", sub, command, dot)
}

func (s *RedisServer) subcommandError(sub string, command string) RESPValue {
	if s.profile.modernErrors() {
		return errorf("ERR unknown subcommand '%s'. Try %s HELP.", truncateBytes(sub, 128), command)
	}
	return s.legacySubcommandError(sub, command)
}

func (s *RedisServer) handleAuth(args []string) RESPValue {
	password := s.configValue("requirepass")
	if !s.profile.atLeast(6, 0) {
		if password == "" {
			return ErrorReply("ERR Client sent AUTH, but no password is set")
		}
		// A honeypot accepts any password so the session continues.
		return SimpleString("OK")
	}
	if len(args) > 3 {
		return syntaxError
	}
	if len(args) == 3 {
		if args[1] != "default" {
			return wrongPassReply
		}
		return SimpleString("OK")
	}
	if password == "" {
		return ErrorReply("ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?")
	}
	return SimpleString("OK")
}

func (s *RedisServer) handleHello(state *clientState, args []string) RESPValue {
	proto := state.proto
	if len(args) >= 2 {
		version, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return ErrorReply("ERR Protocol version is not an integer or out of range")
		}
		if version < 2 || version > 3 {
			return ErrorReply("NOPROTO unsupported protocol version")
		}
		proto = int(version)
	}

	name := state.name
	for i := 2; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "auth":
			if i+2 >= len(args) {
				return errorf("ERR Syntax error in HELLO option '%s'", args[i])
			}
			if args[i+1] != "default" {
				return wrongPassReply
			}
			i += 2
		case "setname":
			if i+1 >= len(args) {
				return errorf("ERR Syntax error in HELLO option '%s'", args[i])
			}
			if !validClientName(args[i+1]) {
				return ErrorReply("ERR Client names cannot contain spaces, newlines or special characters.")
			}
			name = capClientAttr(args[i+1])
			i++
		default:
			return errorf("ERR Syntax error in HELLO option '%s'", args[i])
		}
	}
	state.proto = proto
	state.name = name

	role := "master"
	if s.isReplica(state) {
		role = "replica"
	}
	return Map(
		BulkString("server"), BulkString(s.profile.Flavor),
		BulkString("version"), BulkString(s.profile.Version),
		BulkString("proto"), IntegerReply(int64(proto)),
		BulkString("id"), IntegerReply(int64(state.id)),
		BulkString("mode"), BulkString("standalone"),
		BulkString("role"), BulkString(role),
		BulkString("modules"), s.moduleList(),
	)
}

func (s *RedisServer) handleSet(state *clientState, args []string) RESPValue {
	var nx, xx, get, keepTTL bool
	var expireAt time.Time
	expireSet := false
	modern := s.profile.atLeast(6, 2)

	for i := 3; i < len(args); i++ {
		option := strings.ToUpper(args[i])
		switch {
		case option == "NX" && !xx && (!get || s.profile.atLeast(7, 0)):
			nx = true
		case option == "XX" && !nx:
			xx = true
		case option == "GET" && modern && (!nx || s.profile.atLeast(7, 0)):
			get = true
		case option == "KEEPTTL" && s.profile.atLeast(6, 0) && !expireSet:
			keepTTL = true
		case (option == "EX" || option == "PX" || (modern && (option == "EXAT" || option == "PXAT"))) && !expireSet && !keepTTL && i+1 < len(args):
			amount, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil {
				return notIntegerErr
			}
			ms, valid := expireMillis(amount, option == "EX" || option == "EXAT",
				option == "EXAT" || option == "PXAT", modern)
			if amount <= 0 || !valid {
				if s.profile.modernErrors() {
					return ErrorReply("ERR invalid expire time in 'set' command")
				}
				return ErrorReply("ERR invalid expire time in set")
			}
			expireAt = time.UnixMilli(ms)
			expireSet = true
			i++
		default:
			return syntaxError
		}
	}

	old, exists := s.store.Get(state.db, args[1])
	oldReply := NilBulkString()
	if exists {
		oldReply = BulkString(old)
	}
	if (nx && exists) || (xx && !exists) {
		if get {
			return oldReply
		}
		return NilBulkString()
	}

	if !s.store.SetWithExpiry(state.db, args[1], args[2], expireAt, keepTTL) {
		return oomError
	}
	s.runtime.markDirty(1)
	if get {
		return oldReply
	}
	return SimpleString("OK")
}

// oomError is Redis' answer to a write above maxmemory.
var oomError = ErrorReply("OOM command not allowed when used memory > 'maxmemory'.")

// expireMillis turns an expire argument into absolute Unix milliseconds. With
// checked set it reports an overflow like Redis 6.2 and later; older servers
// compute with wrapping integers, which is what this does then too.
func expireMillis(amount int64, seconds bool, absolute bool, checked bool) (int64, bool) {
	ms := amount
	if seconds {
		if checked && (ms > math.MaxInt64/1000 || ms < math.MinInt64/1000) {
			return 0, false
		}
		ms *= 1000
	}
	if !absolute {
		now := time.Now().UnixMilli()
		if checked && ms > math.MaxInt64-now {
			return 0, false
		}
		ms += now
	}
	return ms, true
}

func (s *RedisServer) handleExpire(state *clientState, name string, args []string) RESPValue {
	amount, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		return notIntegerErr
	}
	if len(args) > 3 {
		if !s.profile.atLeast(7, 0) {
			return wrongArity(name)
		}
		for _, option := range args[3:] {
			switch strings.ToUpper(option) {
			case "NX", "XX", "GT", "LT":
			default:
				return errorf("ERR Unsupported option %s", option)
			}
		}
	}
	ms, valid := expireMillis(amount, name == "expire", false, s.profile.atLeast(7, 0))
	if !valid {
		return errorf("ERR invalid expire time in '%s' command", name)
	}
	if s.store.Expire(state.db, args[1], time.UnixMilli(ms)) {
		return IntegerReply(1)
	}
	return IntegerReply(0)
}

func (s *RedisServer) handleScan(state *clientState, args []string) commandResult {
	if _, err := strconv.ParseUint(args[1], 10, 64); err != nil {
		return ok(ErrorReply("ERR invalid cursor"))
	}
	pattern := "*"
	typeFilter := ""
	for i := 2; i < len(args); i++ {
		if i+1 >= len(args) {
			return ok(syntaxError)
		}
		switch strings.ToUpper(args[i]) {
		case "MATCH":
			pattern = args[i+1]
		case "COUNT":
			count, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil {
				return ok(notIntegerErr)
			}
			if count < 1 {
				return ok(syntaxError)
			}
		case "TYPE":
			typeFilter = strings.ToLower(args[i+1])
		default:
			return ok(syntaxError)
		}
		i++
	}
	if typeFilter != "" && typeFilter != "string" {
		return ok(Array(BulkString("0"), Array()))
	}
	return s.keysResult(state.db, pattern, func(keys RESPValue) RESPValue {
		return Array(BulkString("0"), keys)
	})
}

// keysResult answers KEYS and SCAN. What their reply costs counts against
// MaxReplyBytes before it is built; when it does not fit, the connection is
// closed without a reply, like Redis' output buffer limit.
func (s *RedisServer) keysResult(db int, pattern string, wrap func(RESPValue) RESPValue) commandResult {
	var reserved int64
	keys, fits := s.store.KeysWithin(db, pattern, func(cost int64) bool {
		if cost < largeReplyBytes {
			return true
		}
		if !s.reserveReply(cost) {
			return false
		}
		reserved = cost
		return true
	})
	if !fits {
		return commandResult{reply: RawReply(""), silent: true, close: true, replyLimited: true}
	}
	reply := BulkArray(keys)
	if wrap != nil {
		reply = wrap(reply)
	}
	result := ok(reply)
	result.reserved = reserved
	return result
}

func (s *RedisServer) configValue(key string) string {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.config[key]
}

func (s *RedisServer) handleConfig(state *clientState, args []string) RESPValue {
	modern := s.profile.modernErrors()
	if len(args) < 2 {
		return wrongArity("config")
	}

	switch strings.ToLower(args[1]) {
	case "get":
		if !modern && len(args) != 3 {
			return s.legacySubcommandError(args[1], "CONFIG")
		}
		return s.configGet(args[2:])
	case "set":
		if !modern && len(args) != 4 {
			return s.legacySubcommandError(args[1], "CONFIG")
		}
		if len(args)%2 != 0 {
			return wrongArity("config|set")
		}
		return s.configSet(state, args[2:])
	case "rewrite":
		if s.profile.ConfigFile == "" {
			return ErrorReply("ERR The server is running without a config file")
		}
		return SimpleString("OK")
	case "resetstat":
		s.keyspaceHits.Store(0)
		s.keyspaceMisses.Store(0)
		s.protocolErrors.Store(0)
		s.stats.reset()
		return SimpleString("OK")
	case "help":
		return BulkArray(configHelp)
	default:
		return s.subcommandError(args[1], "CONFIG")
	}
}

var configHelp = []string{
	"CONFIG <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",
	"GET <pattern>",
	"    Return parameters matching the glob-like <pattern> and their values.",
	"SET <directive> <value>",
	"    Set the configuration <directive> to <value>.",
	"RESETSTAT",
	"    Reset statistics reported by the INFO command.",
	"REWRITE",
	"    Rewrite the configuration file.",
	"HELP",
	"    Print this help.",
}

func (s *RedisServer) configGet(patterns []string) RESPValue {
	s.configMu.RLock()
	defer s.configMu.RUnlock()

	// Redis returns matches sorted; Valkey groups them by pattern order.
	seen := make(map[string]bool)
	var keys []string
	for _, pattern := range patterns {
		var group []string
		for key := range s.config {
			if !seen[key] && stringMatch(pattern, key, true) {
				seen[key] = true
				group = append(group, key)
			}
		}
		sort.Strings(group)
		keys = append(keys, group...)
	}
	if !s.profile.isValkey() {
		sort.Strings(keys)
	}

	items := make([]RESPValue, 0, len(keys)*2)
	for _, key := range keys {
		items = append(items, BulkString(key), BulkString(s.config[key]))
	}
	return Map(items...)
}

// configCharge is what a config value takes from the data budget: the bytes
// it has beyond the persona's default value.
func (s *RedisServer) configCharge(key, value string) int64 {
	if extra := len(value) - len(s.configDefaults[key]); extra > 0 {
		return int64(extra)
	}
	return 0
}

var immutableConfigs = map[string]bool{
	"daemonize": true, "databases": true, "logfile": true, "pidfile": true,
	"supervised": true, "unixsocket": true, "unixsocketperm": true, "aclfile": true,
	"io-threads": true, "cluster-enabled": true, "cluster-config-file": true,
	"appenddirname": true, "enable-protected-configs": true, "enable-module-command": true,
	"enable-debug-command": true, "syslog-enabled": true, "syslog-ident": true,
	"syslog-facility": true, "always-show-logo": true, "set-proc-title": true,
}

var protectedConfigs = map[string]bool{"dir": true, "dbfilename": true}

// configSet validates all pairs first, then applies them, matching Redis'
// all-or-nothing CONFIG SET.
func (s *RedisServer) configSet(state *clientState, pairs []string) RESPValue {
	modern := s.profile.modernErrors()
	updates := make(map[string]string, len(pairs)/2)

	s.configMu.RLock()
	currentDir := s.config["dir"]
	protectedMode := s.config["enable-protected-configs"]
	s.configMu.RUnlock()

	for i := 0; i+1 < len(pairs); i += 2 {
		key, value := strings.ToLower(pairs[i]), pairs[i+1]
		failed := func(reason string) RESPValue {
			return errorf("ERR CONFIG SET failed (possibly related to argument '%s') - %s", key, reason)
		}

		s.configMu.RLock()
		_, known := s.config[key]
		s.configMu.RUnlock()
		if !known || (!modern && immutableConfigs[key]) {
			if modern {
				return errorf("ERR Unknown option or number of arguments for CONFIG SET - '%s'", key)
			}
			return errorf("ERR Unsupported CONFIG parameter: %s", key)
		}
		if _, dup := updates[key]; dup {
			return failed("duplicate parameter")
		}
		if modern && immutableConfigs[key] {
			return failed("can't set immutable config")
		}
		if modern && protectedConfigs[key] && !(protectedMode == "yes" || (protectedMode == "local" && state.trustedLocal)) {
			return failed("can't set protected config")
		}

		switch key {
		case "dir":
			target := value
			if !path.IsAbs(target) {
				target = path.Join(currentDir, target)
			}
			target = path.Clean(target)
			if !fakeDirExists(target, currentDir) {
				if modern {
					return failed("No such file or directory")
				}
				return ErrorReply("ERR Changing directory: No such file or directory")
			}
			value = target
		case "dbfilename":
			if strings.Contains(value, "/") {
				switch {
				case modern:
					return failed("dbfilename can't be a path, just a filename")
				case s.profile.atLeast(6, 0):
					return errorf("ERR Invalid argument '%s' for CONFIG SET 'dbfilename' - dbfilename can't be a path, just a filename", value)
				default:
					return ErrorReply("ERR dbfilename can't be a path, just a filename")
				}
			}
		}
		updates[key] = value
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()
	var delta int64
	for key, value := range updates {
		delta += s.configCharge(key, value) - s.configCharge(key, s.config[key])
	}
	if delta > 0 && !s.budget.reserve(delta) {
		return oomError
	}
	for key, value := range updates {
		s.config[key] = value
	}
	if delta < 0 {
		s.budget.release(-delta)
	}
	return SimpleString("OK")
}

// fakeDirs are directories a typical Linux host has; CONFIG SET dir accepts
// them so file-write attacks proceed, and rejects random paths like Redis.
var fakeDirs = func() map[string]bool {
	dirs := map[string]bool{}
	for _, dir := range []string{
		"/", "/bin", "/boot", "/data", "/dev", "/dev/shm", "/etc", "/etc/cron.d",
		"/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly",
		"/etc/init.d", "/etc/profile.d", "/etc/redis", "/etc/ssh", "/etc/systemd/system",
		"/home", "/lib", "/media", "/mnt", "/opt", "/proc", "/root", "/root/.ssh",
		"/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/usr/bin", "/usr/lib",
		"/usr/local", "/usr/local/bin", "/usr/local/lib", "/usr/sbin", "/usr/share",
		"/usr/share/nginx", "/usr/share/nginx/html", "/var", "/var/backups", "/var/cache",
		"/var/lib", "/var/lib/redis", "/var/lib/redis/6379", "/var/log", "/var/log/redis",
		"/var/mail", "/var/opt", "/var/run", "/var/run/redis", "/var/spool",
		"/var/spool/cron", "/var/spool/cron/crontabs", "/var/tmp", "/var/www", "/var/www/html",
	} {
		dirs[dir] = true
	}
	for _, user := range []string{"admin", "centos", "debian", "deploy", "ec2-user", "git", "oracle", "pi", "postgres", "redis", "test", "ubuntu", "user"} {
		dirs["/home/"+user] = true
		dirs["/home/"+user+"/.ssh"] = true
	}
	return dirs
}()

func fakeDirExists(dir string, configured string) bool {
	return fakeDirs[dir] || dir == configured
}

// maxClientAttrBytes caps what a connection keeps of its name and library
// fields; Redis keeps any length, real clients send a few dozen bytes.
const maxClientAttrBytes = 4096

func capClientAttr(value string) string {
	return truncateBytes(value, maxClientAttrBytes)
}

func validClientName(name string) bool {
	for i := 0; i < len(name); i++ {
		if name[i] < '!' || name[i] > '~' {
			return false
		}
	}
	return true
}

func (s *RedisServer) handleClient(state *clientState, args []string) RESPValue {
	if len(args) < 2 {
		return wrongArity("client")
	}
	modern := s.profile.modernErrors()
	legacy := func() RESPValue { return s.legacySubcommandError(args[1], "CLIENT") }

	switch strings.ToLower(args[1]) {
	case "setname":
		if len(args) != 3 {
			return legacy()
		}
		if !validClientName(args[2]) {
			return ErrorReply("ERR Client names cannot contain spaces, newlines or special characters.")
		}
		state.name = capClientAttr(args[2])
		if args[2] == HealthcheckClientName && state.trustedLocal {
			state.suppressLogs = true
		}
		return SimpleString("OK")
	case "setinfo":
		if !s.profile.atLeast(7, 2) {
			return legacy()
		}
		var target *string
		switch strings.ToLower(args[2]) {
		case "lib-name":
			target = &state.libName
		case "lib-ver":
			target = &state.libVersion
		default:
			return errorf("ERR Unrecognized option '%s'", truncateBytes(args[2], 128))
		}
		if !validClientName(args[3]) {
			return errorf("ERR %s cannot contain spaces, newlines or special characters.", args[2])
		}
		*target = capClientAttr(args[3])
		return SimpleString("OK")
	case "getname":
		if len(args) != 2 {
			return legacy()
		}
		if state.name == "" {
			return NilBulkString()
		}
		return BulkString(state.name)
	case "id":
		if len(args) != 2 {
			return legacy()
		}
		return IntegerReply(int64(state.id))
	case "info":
		if !s.profile.atLeast(6, 2) || len(args) != 2 {
			return legacy()
		}
		return VerbatimText(s.clientInfoLine(state, "info"))
	case "list":
		return VerbatimText(s.clientInfoLine(state, "list"))
	case "kill":
		if len(args) == 3 {
			return ErrorReply("ERR No such client")
		}
		return IntegerReply(0)
	case "help":
		return BulkArray([]string{
			"CLIENT <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",
			"GETNAME",
			"    Return the name of the current connection.",
			"ID",
			"    Return the ID of the current connection.",
			"INFO",
			"    Return information about the current client connection.",
			"LIST [options ...]",
			"    Return information about client connections.",
			"SETNAME <connection-name>",
			"    Assign the name <connection-name> to the current connection.",
			"HELP",
			"    Print this help.",
		})
	default:
		if modern {
			// The subcommand is known to this persona (checked in
			// handleCommand) but not emulated in detail.
			return SimpleString("OK")
		}
		return legacy()
	}
}

func (s *RedisServer) handleCommandCommand(args []string) RESPValue {
	data := s.profile.data
	if len(args) == 1 {
		return RawReply(string(data.commandsRaw))
	}
	modern := s.profile.modernErrors()

	switch strings.ToLower(args[1]) {
	case "count":
		if len(args) != 2 {
			return s.subcommandError(args[1], "COMMAND")
		}
		return IntegerReply(int64(len(data.commands)))
	case "info":
		if len(args) == 2 && modern {
			return RawReply(string(data.commandsRaw))
		}
		if len(args) == 2 {
			return s.subcommandError(args[1], "COMMAND")
		}
		var raw strings.Builder
		fmt.Fprintf(&raw, "*%d\r\n", len(args)-2)
		for _, name := range args[2:] {
			if entry, found := s.lookupCommandEntry(name); found {
				raw.Write(entry.raw)
			} else {
				raw.WriteString("$-1\r\n")
			}
		}
		return RawReply(raw.String())
	case "docs":
		if data.docs == nil {
			return s.subcommandError(args[1], "COMMAND")
		}
		if len(args) == 2 {
			return RawReply(string(data.docsRaw))
		}
		var body strings.Builder
		found := 0
		for _, name := range args[2:] {
			if pair, ok := data.docs[strings.ToLower(name)]; ok {
				body.Write(pair)
				found++
			}
		}
		return RawReply(fmt.Sprintf("*%d\r\n", found*2) + body.String())
	case "list":
		if !modern {
			return s.subcommandError(args[1], "COMMAND")
		}
		names := make([]string, 0, len(data.commands))
		for name := range data.commands {
			names = append(names, name)
		}
		sort.Strings(names)
		return BulkArray(names)
	case "help":
		return BulkArray([]string{
			"COMMAND <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",
			"(no subcommand)",
			"    Return details about all Redis commands.",
			"COUNT",
			"    Return the total number of commands in this Redis server.",
			"INFO [<command-name> ...]",
			"    Return details about multiple Redis commands.",
			"HELP",
			"    Print this help.",
		})
	default:
		if modern {
			return Array()
		}
		return s.subcommandError(args[1], "COMMAND")
	}
}

func (s *RedisServer) lookupCommandEntry(name string) (commandEntry, bool) {
	name = strings.ToLower(name)
	if parent, _, isSub := strings.Cut(name, "|"); isSub {
		entry, ok := s.profile.data.commands[parent]
		if !ok {
			return commandEntry{}, false
		}
		sub, ok := entry.subcommands[name]
		return sub, ok
	}
	entry, ok := s.profile.data.commands[name]
	return entry, ok
}

// moduleList converts the recorded MODULE LIST entries into maps so they
// encode as RESP3 maps for HELLO 3 clients.
func (s *RedisServer) moduleList() RESPValue {
	items := make([]RESPValue, 0, len(s.profile.data.modules))
	for _, module := range s.profile.data.modules {
		pairs := make([]RESPValue, 0, len(module.children))
		for _, child := range module.children {
			pairs = append(pairs, child.toValue())
		}
		items = append(items, Map(pairs...))
	}
	return Array(items...)
}

func (s *RedisServer) handleModule(state *clientState, args []string) RESPValue {
	if len(args) < 2 {
		return wrongArity("module")
	}
	sub := strings.ToLower(args[1])
	// LOAD, LOADEX and UNLOAD are protected commands in Redis 7+.
	if s.profile.atLeast(7, 0) && (sub == "load" || sub == "loadex" || sub == "unload") {
		setting := s.configValue("enable-module-command")
		if setting != "yes" && !(setting == "local" && state.trustedLocal) {
			return ErrorReply(`ERR MODULE command not allowed. If the enable-module-command option is set to "local", you can run it from a local connection, otherwise you need to set this option in the configuration file, and then restart the server.`)
		}
	}

	switch sub {
	case "list":
		if len(args) != 2 {
			return s.legacySubcommandError(args[1], "MODULE")
		}
		return s.moduleList()
	case "load", "loadex":
		if len(args) < 3 {
			return s.legacySubcommandError(args[1], "MODULE")
		}
		// No module file can exist: the honeypot never performs the
		// replication transfer that would have written it.
		return ErrorReply("ERR Error loading the extension. Please check the server logs.")
	case "unload":
		if len(args) != 3 {
			return s.legacySubcommandError(args[1], "MODULE")
		}
		return ErrorReply("ERR Error unloading module: no such module with that name")
	case "help":
		return BulkArray([]string{
			"MODULE <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",
			"LIST",
			"    Return a list of loaded modules.",
			"LOAD <path> [<arg> ...]",
			"    Load a module library from <path>, passing to it any optional arguments.",
			"UNLOAD <name>",
			"    Unload a module.",
			"HELP",
			"    Print this help.",
		})
	default:
		return s.subcommandError(args[1], "MODULE")
	}
}

func (s *RedisServer) handleDebug(state *clientState, args []string) RESPValue {
	if s.profile.atLeast(7, 0) {
		setting := s.configValue("enable-debug-command")
		if setting != "yes" && !(setting == "local" && state.trustedLocal) {
			return ErrorReply(`ERR DEBUG command not allowed. If the enable-debug-command option is set to "local", you can run it from a local connection, otherwise you need to set this option in the configuration file, and then restart the server.`)
		}
	}
	return s.subcommandError(args[1], "DEBUG")
}
