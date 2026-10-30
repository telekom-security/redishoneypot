package honeypot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxLoggedArgsBytes           = 512
	defaultMaxLoggedPayloadBytes = 8192
	// maxLoggedFieldBytes caps every other attacker controlled log field.
	maxLoggedFieldBytes = 1024
	// maxLoggedClientBytes caps the client name and library fields, which go
	// into every line of a session.
	maxLoggedClientBytes = 128
	// maxLogLineBytes caps a whole JSON line; above it the largest attacker
	// fields are dropped and the line carries log_truncated.
	maxLogLineBytes = 64 * 1024
)

// NewJSONLogger writes one JSON object per line, each at most maxLogLineBytes.
func NewJSONLogger(w io.Writer) *slog.Logger {
	return newCappedJSONLogger(w, maxLogLineBytes)
}

func newCappedJSONLogger(w io.Writer, limit int) *slog.Logger {
	core := &lineCapCore{w: w, limit: limit}
	return slog.New(&lineCapHandler{core: core, inner: newJSONHandler(&core.buf)})
}

func newJSONHandler(w io.Writer) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Value.Kind() == slog.KindAny && attr.Value.Any() == nil {
				return slog.Attr{}
			}
			switch attr.Key {
			case slog.TimeKey:
				attr.Key = "timestamp"
				attr.Value = slog.StringValue(formatLogTime(attr.Value.Time()))
			case slog.MessageKey:
				attr.Key = "message"
			case slog.LevelKey:
				attr.Value = slog.StringValue(attr.Value.String())
			}
			return attr
		},
	})
}

type lineCapCore struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	w     io.Writer
	limit int
}

// lineCapHandler encodes each record into a buffer first, so a line over the
// limit can be encoded again without its largest fields before it is written.
type lineCapHandler struct {
	core  *lineCapCore
	inner slog.Handler
}

// keptLogFields are never dropped from an oversized line.
var keptLogFields = map[string]bool{
	"event": true, "protocol": true, "network": true, "profile": true,
	"session_id": true, "src_ip": true, "dest_ip": true, "session_start": true,
	"session_end": true, "command": true, "command_category": true,
	"outcome": true, "analysis_hint": true, "reason": true, "error": true,
}

func (h *lineCapHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *lineCapHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &lineCapHandler{core: h.core, inner: h.inner.WithAttrs(attrs)}
}

func (h *lineCapHandler) WithGroup(name string) slog.Handler {
	return &lineCapHandler{core: h.core, inner: h.inner.WithGroup(name)}
}

func (h *lineCapHandler) Handle(ctx context.Context, record slog.Record) error {
	c := h.core
	c.mu.Lock()
	defer c.mu.Unlock()

	c.buf.Reset()
	if err := h.inner.Handle(ctx, record); err != nil {
		return err
	}
	if c.limit > 0 && c.buf.Len() > c.limit {
		attrs := make([]slog.Attr, 0, record.NumAttrs()+1)
		record.Attrs(func(attr slog.Attr) bool {
			attrs = append(attrs, attr)
			return true
		})
		for c.buf.Len() > c.limit {
			largest := -1
			for i, attr := range attrs {
				if keptLogFields[attr.Key] || attr.Value.Kind() != slog.KindString {
					continue
				}
				if largest < 0 || len(attr.Value.String()) > len(attrs[largest].Value.String()) {
					largest = i
				}
			}
			if largest < 0 {
				break
			}
			attrs = append(attrs[:largest], attrs[largest+1:]...)
			shrunk := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
			shrunk.AddAttrs(attrs...)
			shrunk.AddAttrs(slog.Bool("log_truncated", true))
			c.buf.Reset()
			if err := h.inner.Handle(ctx, shrunk); err != nil {
				return err
			}
		}
	}
	_, err := c.w.Write(c.buf.Bytes())
	return err
}

func (s *RedisServer) logConnect(state *clientState, conn net.Conn) {
	attrs := s.baseLogAttrs("connect", state, conn, time.Time{})
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "connect", attrs...)
}

func (s *RedisServer) logProtocolError(state *clientState, conn net.Conn, err error) {
	attrs := s.baseLogAttrs("protocol_error", state, conn, time.Time{})
	attrs = append(attrs,
		slog.String("error", err.Error()),
		slog.Int("max_bulk_bytes", s.options.MaxBulkBytes),
		slog.Int("max_inline_bytes", s.options.MaxInlineBytes),
		slog.Int("max_array_elems", s.options.MaxArrayElems),
	)
	s.logger.LogAttrs(context.Background(), slog.LevelWarn, "protocol_error", attrs...)
}

func (s *RedisServer) logCommand(state *clientState, conn net.Conn, args []string, result commandResult, responseBytes int) {
	attrs := s.baseLogAttrs("command", state, conn, time.Time{})
	command := strings.ToUpper(args[0])
	logArgs := redactedArgsForLog(args)

	attrs = append(attrs, slog.Int("redis_db", state.db))
	attrs = appendCapped(attrs, "command", command, maxLoggedFieldBytes)
	attrs = append(attrs,
		slog.String("command_category", commandCategory(command)),
		slog.Int("arg_count", len(args)-1),
		slog.String("response_class", result.reply.Class()),
		slog.Int("response_bytes", responseBytes),
		slog.String("outcome", commandOutcome(result)),
		slog.Bool("close_after_command", result.close),
	)
	if result.replyLimited {
		attrs = append(attrs, slog.Bool("reply_limited", true))
	}
	if len(logArgs) > 1 {
		argsText, argsTruncated := joinArgsForLog(logArgs[1:], maxLoggedArgsBytes)
		attrs = append(attrs,
			slog.String("args_text", argsText),
			slog.Bool("args_truncated", argsTruncated),
			slog.String("args_sha256", hashArgs(args[1:])),
		)
	}
	attrs = append(attrs, s.sessionAnalysisAttrs(state, args, result)...)
	attrs = append(attrs, iocAttrs(logArgs[1:])...)

	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "command", attrs...)
}

func (s *RedisServer) logClose(state *clientState, conn net.Conn, endedAt time.Time) {
	attrs := s.baseLogAttrs("close", state, conn, endedAt)
	attrs = append(attrs, slog.Int64("session_command_count", state.commands))
	if len(state.hints) > 0 {
		attrs = append(attrs, slog.String("session_hints", strings.Join(state.hints, " ")))
	}
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "close", attrs...)
}

func (s *RedisServer) baseLogAttrs(event string, state *clientState, conn net.Conn, sessionEnd time.Time) []slog.Attr {
	srcIP, srcPort := splitAddr(conn.RemoteAddr())
	destIP, destPort := splitAddr(conn.LocalAddr())

	now := time.Now()
	elapsedUntil := now
	if !sessionEnd.IsZero() {
		elapsedUntil = sessionEnd
	}
	elapsed := elapsedUntil.Sub(state.connected)
	if elapsed < 0 {
		elapsed = 0
	}

	attrs := []slog.Attr{
		slog.String("event", event),
		slog.String("protocol", "redis"),
		slog.String("network", s.options.Network),
		slog.String("profile", s.profile.Name),
		slog.String("session_id", state.sessionID),
		slog.Uint64("client_id", state.id),
		slog.String("src_ip", srcIP),
		slog.Int("src_port", srcPort),
		slog.String("dest_ip", destIP),
		slog.Int("dest_port", destPort),
		slog.String("session_start", formatLogTime(state.connected)),
		slog.Float64("session_duration", elapsed.Seconds()),
		slog.Int64("session_duration_ms", elapsed.Milliseconds()),
	}
	if !sessionEnd.IsZero() {
		attrs = append(attrs, slog.String("session_end", formatLogTime(sessionEnd)))
	}
	attrs = appendNonEmptyCapped(attrs, "client_name", state.name, maxLoggedClientBytes)
	attrs = appendNonEmptyCapped(attrs, "client_library_name", state.libName, maxLoggedClientBytes)
	attrs = appendNonEmptyCapped(attrs, "client_library_version", state.libVersion, maxLoggedClientBytes)
	attrs = appendNonEmptyCapped(attrs, "user_agent", state.userAgent(), 2*maxLoggedClientBytes+1)

	return attrs
}

func appendNonEmptyCapped(attrs []slog.Attr, key string, value string, limit int) []slog.Attr {
	if value == "" {
		return attrs
	}
	return appendCapped(attrs, key, value, limit)
}

// appendCapped logs an attacker controlled string cut to limit bytes on a rune
// boundary; a cut value gets <key>_truncated next to it.
func appendCapped(attrs []slog.Attr, key string, value string, limit int) []slog.Attr {
	text, truncated := capString(value, limit)
	attrs = append(attrs, slog.String(key, text))
	if truncated {
		attrs = append(attrs, slog.Bool(key+"_truncated", true))
	}
	return attrs
}

func capString(value string, limit int) (string, bool) {
	if len(value) <= limit {
		return value, false
	}
	return joinArgsForLog([]string{value}, limit)
}

func formatLogTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func splitAddr(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 0
	}
	return host, port
}

func joinArgsForLog(args []string, limit int) (string, bool) {
	if len(args) == 0 {
		return "", false
	}

	var builder strings.Builder
	truncated := false
	for i, arg := range args {
		if i > 0 {
			builder.WriteByte(' ')
		}
		remaining := limit - builder.Len()
		if remaining <= 0 {
			truncated = true
			break
		}
		if len(arg) > remaining {
			// Cut on a rune boundary so the log does not end in a broken
			// UTF-8 sequence.
			for remaining > 0 && !utf8.RuneStart(arg[remaining]) {
				remaining--
			}
			builder.WriteString(arg[:remaining])
			truncated = true
			break
		}
		builder.WriteString(arg)
	}
	return builder.String(), truncated
}

func redactedArgsForLog(args []string) []string {
	out := append([]string(nil), args...)
	if len(out) == 0 {
		return out
	}

	switch strings.ToLower(out[0]) {
	case "auth":
		if len(out) == 2 {
			out[1] = "[password redacted]"
		}
		if len(out) == 3 {
			out[2] = "[password redacted]"
		}
	case "config":
		if len(out) >= 4 && strings.EqualFold(out[1], "set") {
			for i := 2; i+1 < len(out); i += 2 {
				if isSecretConfig(out[i]) {
					out[i+1] = "[password redacted]"
				}
			}
		}
	case "hello":
		for i := 2; i < len(out); i++ {
			if strings.EqualFold(out[i], "auth") && i+2 < len(out) {
				out[i+2] = "[password redacted]"
				i += 2
			}
		}
	case "migrate":
		for i := 6; i < len(out); i++ {
			switch strings.ToLower(out[i]) {
			case "auth":
				if i+1 < len(out) {
					out[i+1] = "[password redacted]"
					i++
				}
			case "auth2":
				if i+2 < len(out) {
					out[i+2] = "[password redacted]"
					i += 2
				}
			}
		}
	}
	return out
}

// isSecretConfig names the CONFIG SET keys whose values are passwords.
func isSecretConfig(key string) bool {
	switch strings.ToLower(key) {
	case "requirepass", "masterauth":
		return true
	}
	return false
}

func hashArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	sum := sha256.New()
	for _, arg := range args {
		_, _ = sum.Write([]byte(arg))
		_, _ = sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func hashString(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func commandOutcome(result commandResult) string {
	switch {
	case result.silent:
		return "connection_closed"
	case result.reply.kind == respError:
		return "error"
	default:
		return "success"
	}
}

// sessionAnalysisAttrs adds analysis fields that depend on what the session
// did before: a SAVE after CONFIG SET dir/dbfilename commits a file write.
func (s *RedisServer) sessionAnalysisAttrs(state *clientState, args []string, result commandResult) []slog.Attr {
	attrs := commandAnalysisAttrsLimit(args, s.options.MaxLoggedPayloadBytes)
	command := strings.ToLower(args[0])
	succeeded := result.reply.kind != respError

	switch command {
	case "config":
		if succeeded && len(args) >= 4 && strings.EqualFold(args[1], "set") {
			for i := 2; i+1 < len(args); i += 2 {
				if key := strings.ToLower(args[i]); key == "dir" || key == "dbfilename" {
					state.writeTargetSet = true
				}
			}
		}
	case "save", "bgsave":
		if succeeded && state.writeTargetSet && len(attrs) > 0 && attrs[0].Key == "analysis_hint" {
			attrs[0] = slog.String("analysis_hint", "redis_write_file_commit")
			attrs = appendCapped(attrs, "target_dir", s.configValue("dir"), maxLoggedFieldBytes)
			attrs = appendCapped(attrs, "target_dbfilename", s.configValue("dbfilename"), maxLoggedFieldBytes)
		}
	}

	if len(attrs) > 0 && attrs[0].Key == "analysis_hint" {
		state.addHint(attrs[0].Value.String())
	}
	return attrs
}

func commandAnalysisAttrs(args []string) []slog.Attr {
	return commandAnalysisAttrsLimit(args, defaultMaxLoggedPayloadBytes)
}

func commandAnalysisAttrsLimit(args []string, payloadLimit int) []slog.Attr {
	if len(args) == 0 {
		return nil
	}

	command := strings.ToLower(args[0])
	attrs := []slog.Attr{}

	switch command {
	case "get", "set", "type", "ttl":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "key", args[1], maxLoggedFieldBytes)
			attrs = append(attrs, slog.Int("key_count", 1))
		}
		if command == "set" && len(args) > 2 {
			valueText, truncated := joinArgsForLog([]string{args[2]}, payloadLimit)
			attrs = append(attrs,
				slog.Int("value_size", len(args[2])),
				slog.String("value_sha256", hashString(args[2])),
				slog.String("value_text", valueText),
				slog.Bool("value_truncated", truncated),
			)
		}
	case "mget", "del", "exists":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "key", args[1], maxLoggedFieldBytes)
			attrs = append(attrs, slog.Int("key_count", len(args)-1))
		}
	case "keys":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "key_pattern", args[1], maxLoggedFieldBytes)
		}
	case "config":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "config_subcommand", strings.ToLower(args[1]), maxLoggedFieldBytes)
		}
		if len(args) > 2 {
			attrs = appendCapped(attrs, "config_key", strings.ToLower(args[2]), maxLoggedFieldBytes)
		}
		if len(args) > 3 {
			value := args[3]
			if isSecretConfig(args[2]) {
				value = "[password redacted]"
			}
			valueText, truncated := joinArgsForLog([]string{value}, payloadLimit)
			attrs = append(attrs,
				slog.String("config_value", valueText),
				slog.Bool("config_value_truncated", truncated),
				slog.String("config_value_sha256", hashString(args[3])),
			)
		}
	case "auth":
		passwordIndex := 1
		if len(args) == 3 {
			attrs = appendCapped(attrs, "auth_username", args[1], maxLoggedFieldBytes)
			passwordIndex = 2
		}
		if len(args) > passwordIndex {
			attrs = append(attrs,
				slog.Int("auth_password_length", len(args[passwordIndex])),
				slog.String("auth_password_sha256", hashString(args[passwordIndex])),
			)
		}
	case "slaveof", "replicaof":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "replica_host", args[1], maxLoggedFieldBytes)
		}
		if len(args) > 2 {
			attrs = appendCapped(attrs, "replica_port", args[2], maxLoggedFieldBytes)
		}
	case "replconf":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "replconf_key", strings.ToLower(args[1]), maxLoggedFieldBytes)
		}
		if len(args) > 2 {
			attrs = appendCapped(attrs, "replconf_value", args[2], maxLoggedFieldBytes)
		}
	case "module":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "module_subcommand", strings.ToLower(args[1]), maxLoggedFieldBytes)
		}
		if len(args) > 2 {
			attrs = appendCapped(attrs, "module_path", args[2], maxLoggedFieldBytes)
		}
	case "client":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "client_subcommand", strings.ToLower(args[1]), maxLoggedFieldBytes)
		}
	case "eval", "eval_ro":
		if len(args) > 1 {
			attrs = append(attrs, scriptAttrs(args[1], payloadLimit)...)
		}
		if len(args) > 2 {
			if numKeys, err := strconv.Atoi(args[2]); err == nil {
				attrs = append(attrs, slog.Int("script_numkeys", numKeys))
			}
		}
	case "evalsha", "evalsha_ro":
		if len(args) > 1 {
			attrs = appendCapped(attrs, "script_sha1", strings.ToLower(args[1]), maxLoggedFieldBytes)
		}
	case "script":
		if len(args) > 2 && strings.EqualFold(args[1], "load") {
			attrs = append(attrs, scriptAttrs(args[2], payloadLimit)...)
		}
	case "function":
		if len(args) > 2 && strings.EqualFold(args[1], "load") {
			attrs = append(attrs, scriptAttrs(args[len(args)-1], payloadLimit)...)
		}
	}

	hint := analysisHint(args)
	if len(attrs) == 0 && hint == genericAnalysisHint(command) {
		return nil
	}
	return append([]slog.Attr{slog.String("analysis_hint", hint)}, attrs...)
}

func analysisHint(args []string) string {
	if len(args) == 0 {
		return ""
	}

	switch strings.ToLower(args[0]) {
	case "config":
		if len(args) >= 4 && strings.EqualFold(args[1], "set") {
			switch strings.ToLower(args[2]) {
			case "dir", "dbfilename":
				return "redis_write_file_attempt"
			case "requirepass":
				return "redis_auth_config_attempt"
			}
		}
	case "set":
		if len(args) >= 3 {
			if hint := payloadHint(args[2]); hint != "" {
				return hint
			}
		}
	case "save", "bgsave":
		return "redis_save_attempt"
	case "slaveof", "replicaof", "psync", "sync", "replconf":
		return "redis_replication_attempt"
	case "module":
		if len(args) >= 2 && strings.EqualFold(args[1], "load") {
			return "redis_module_load_attempt"
		}
	case "auth":
		return "redis_auth_attempt"
	case "eval", "eval_ro", "evalsha", "evalsha_ro":
		return "redis_lua_eval"
	case "script":
		if len(args) >= 2 && strings.EqualFold(args[1], "load") {
			return "redis_lua_script_load"
		}
	case "function":
		if len(args) >= 2 && strings.EqualFold(args[1], "load") {
			return "redis_function_load"
		}
	}
	return genericAnalysisHint(args[0])
}

// scriptAttrs describes a Lua script body; the SHA1 matches what EVALSHA
// callers use, so script loads and later calls can be correlated.
func scriptAttrs(body string, payloadLimit int) []slog.Attr {
	text, truncated := joinArgsForLog([]string{body}, payloadLimit)
	return []slog.Attr{
		slog.String("script_sha1", scriptSHA1(body)),
		slog.String("script_sha256", hashString(body)),
		slog.Int("script_size", len(body)),
		slog.String("script_text", text),
		slog.Bool("script_truncated", truncated),
	}
}

var sshKeyMarkers = []string{"ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-", "sk-ssh-ed25519@", "sk-ecdsa-sha2-"}

// cronLine matches a crontab entry: five schedule fields and a command.
var cronLine = regexp.MustCompile(`(?m)^\s*(@(reboot|hourly|daily|weekly|monthly|yearly|annually)|([*0-9,/-]+\s+){4}[*0-9,/A-Za-z-]+)\s+\S`)

// payloadHint classifies values written with SET, which file-write attacks use
// to plant SSH keys or crontab entries.
func payloadHint(value string) string {
	for _, marker := range sshKeyMarkers {
		if strings.Contains(value, marker) {
			return "ssh_key_payload"
		}
	}
	if cronLine.MatchString(value) {
		return "cron_payload"
	}
	return ""
}

func genericAnalysisHint(command string) string {
	return fmt.Sprintf("redis_%s", strings.ToLower(command))
}

const (
	// refusedLogInterval is how often one source address gets a refused line.
	refusedLogInterval = time.Minute
	// maxRefusedSources bounds the addresses whose refusals are counted.
	maxRefusedSources = 4096
)

type refusedLog struct {
	last       time.Time
	suppressed int
}

// logRefused logs a connection refused for a client limit. One source address
// gets at most one line per refusedLogInterval; refused_count includes the
// refusals in between that were not logged.
func (s *RedisServer) logRefused(conn net.Conn, reason string) {
	ip := peerIP(conn.RemoteAddr())
	now := time.Now()

	s.refusedMu.Lock()
	entry := s.refusedLogs[ip]
	if entry != nil && now.Sub(entry.last) < refusedLogInterval {
		entry.suppressed++
		s.refusedMu.Unlock()
		return
	}
	count := 1
	if entry != nil {
		count += entry.suppressed
	}
	if entry == nil && len(s.refusedLogs) >= maxRefusedSources {
		for key, old := range s.refusedLogs {
			if now.Sub(old.last) >= refusedLogInterval {
				delete(s.refusedLogs, key)
			}
		}
		if len(s.refusedLogs) >= maxRefusedSources {
			s.refusedMu.Unlock()
			return
		}
	}
	s.refusedLogs[ip] = &refusedLog{last: now}
	s.refusedMu.Unlock()

	srcIP, srcPort := splitAddr(conn.RemoteAddr())
	destIP, destPort := splitAddr(conn.LocalAddr())
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "refused",
		slog.String("event", "refused"),
		slog.String("protocol", "redis"),
		slog.String("network", s.options.Network),
		slog.String("profile", s.profile.Name),
		slog.String("src_ip", srcIP),
		slog.Int("src_port", srcPort),
		slog.String("dest_ip", destIP),
		slog.Int("dest_port", destPort),
		slog.String("reason", reason),
		slog.Int("refused_count", count),
	)
}
