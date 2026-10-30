package honeypot

import (
	"crypto/sha1"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const maxCachedScripts = 1024

// scriptCache remembers scripts by SHA1 like Redis' script cache. Scripts are
// never executed. It keeps at most maxCachedScripts scripts and
// maxScriptCacheBytes bytes, dropping the oldest, and takes its bytes from the
// data budget; a script that does not fit is answered but not kept.
type scriptCache struct {
	mu      sync.Mutex
	scripts map[string]string
	order   []string
	bytes   int64
	budget  *memBudget
}

func newScriptCacheWithBudget(budget *memBudget) *scriptCache {
	return &scriptCache{scripts: make(map[string]string), budget: budget}
}

func scriptSize(body string) int64 {
	return int64(len(body) + 40 + entryOverhead)
}

func scriptSHA1(body string) string {
	sum := sha1.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

func (c *scriptCache) add(body string) string {
	sha := scriptSHA1(body)
	size := scriptSize(body)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.scripts[sha]; ok || size > maxScriptCacheBytes {
		return sha
	}
	for len(c.order) > 0 && (len(c.order) >= maxCachedScripts || c.bytes+size > maxScriptCacheBytes) {
		c.dropOldest()
	}
	for len(c.order) > 0 && !c.budget.reserve(size) {
		c.dropOldest()
	}
	if len(c.order) == 0 && !c.budget.reserve(size) {
		return sha
	}
	c.scripts[sha] = body
	c.order = append(c.order, sha)
	c.bytes += size
	return sha
}

// dropOldest removes the oldest script. The caller must hold c.mu.
func (c *scriptCache) dropOldest() {
	sha := c.order[0]
	size := scriptSize(c.scripts[sha])
	delete(c.scripts, sha)
	c.order = slices.Delete(c.order, 0, 1)
	c.bytes -= size
	c.budget.release(size)
}

func (c *scriptCache) get(sha string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	body, ok := c.scripts[sha]
	return body, ok
}

func (c *scriptCache) bodies() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.order))
	for _, sha := range c.order {
		out = append(out, c.scripts[sha])
	}
	return out
}

func (c *scriptCache) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.order)
}

func (c *scriptCache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scripts = make(map[string]string)
	c.order = nil
	c.budget.release(c.bytes)
	c.bytes = 0
}

// scriptReply answers a script without running it. Only literal returns are
// recognised; everything else returns nil, which a caller cannot tell apart
// from a script whose last statement returns nothing.
func scriptReply(body string) RESPValue {
	text := strings.TrimSpace(body)
	text = strings.TrimSuffix(text, ";")
	value, ok := strings.CutPrefix(text, "return ")
	if !ok {
		return NilBulkString()
	}
	value = strings.TrimSpace(value)
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		return IntegerReply(n)
	}
	if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] &&
		!strings.ContainsRune(value[1:len(value)-1], rune(value[0])) {
		return BulkString(value[1 : len(value)-1])
	}
	if value == "true" {
		return IntegerReply(1)
	}
	return NilBulkString()
}

func (s *RedisServer) noScriptError() RESPValue {
	if s.profile.isValkey() {
		return ErrorReply("NOSCRIPT No matching script.")
	}
	return ErrorReply("NOSCRIPT No matching script. Please use EVAL.")
}

// checkNumKeys validates the numkeys argument of EVAL-style commands.
func checkNumKeys(args []string) RESPValue {
	numKeys, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		return notIntegerErr
	}
	if numKeys < 0 {
		return ErrorReply("ERR Number of keys can't be negative")
	}
	if numKeys > int64(len(args)-3) {
		return ErrorReply("ERR Number of keys can't be greater than number of args")
	}
	return RESPValue{}
}

func (s *RedisServer) handleEval(name string, args []string) RESPValue {
	if reply := checkNumKeys(args); reply.kind == respError {
		return reply
	}
	if strings.HasPrefix(name, "evalsha") {
		body, found := s.scripts.get(strings.ToLower(args[1]))
		if !found {
			return s.noScriptError()
		}
		return scriptReply(body)
	}
	s.scripts.add(args[1])
	return scriptReply(args[1])
}

func (s *RedisServer) handleScript(args []string) RESPValue {
	switch strings.ToLower(args[1]) {
	case "load":
		if len(args) != 3 {
			return s.legacySubcommandError(args[1], "SCRIPT")
		}
		return BulkString(s.scripts.add(args[2]))
	case "exists":
		if len(args) < 3 {
			return s.legacySubcommandError(args[1], "SCRIPT")
		}
		items := make([]RESPValue, 0, len(args)-2)
		for _, sha := range args[2:] {
			if _, found := s.scripts.get(strings.ToLower(sha)); found {
				items = append(items, IntegerReply(1))
			} else {
				items = append(items, IntegerReply(0))
			}
		}
		return Array(items...)
	case "flush":
		s.scripts.flush()
		return SimpleString("OK")
	case "kill":
		return ErrorReply("NOTBUSY No scripts in execution right now.")
	case "help":
		return BulkArray([]string{
			"SCRIPT <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",
			"EXISTS <sha1> [<sha1> ...]",
			"    Return information about the existence of the scripts in the script cache.",
			"FLUSH [ASYNC|SYNC]",
			"    Flush the Lua scripts cache.",
			"KILL",
			"    Kill the currently executing Lua script.",
			"LOAD <script>",
			"    Load a script into the scripts cache without executing it.",
			"HELP",
			"    Print this help.",
		})
	default:
		return s.subcommandError(args[1], "SCRIPT")
	}
}

func (s *RedisServer) handleFunction(args []string) RESPValue {
	switch strings.ToLower(args[1]) {
	case "list":
		return Array()
	case "load":
		code := args[len(args)-1]
		header, _, _ := strings.Cut(code, "\n")
		if !strings.HasPrefix(header, "#!") {
			return ErrorReply("ERR Missing library metadata")
		}
		for _, field := range strings.Fields(header) {
			if name, ok := strings.CutPrefix(field, "name="); ok && name != "" {
				return BulkString(name)
			}
		}
		return ErrorReply("ERR Library name was not given")
	case "delete":
		return ErrorReply("ERR Library not found")
	case "stats":
		return Map(
			BulkString("running_script"), NilBulkString(),
			BulkString("engines"), Map(
				BulkString("LUA"), Map(
					BulkString("libraries_count"), IntegerReply(0),
					BulkString("functions_count"), IntegerReply(0),
				),
			),
		)
	default:
		return SimpleString("OK")
	}
}
