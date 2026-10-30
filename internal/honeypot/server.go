package honeypot

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultIdleTimeout    = 5 * time.Minute
	defaultMaxBulkBytes   = 1024 * 1024
	defaultMaxInlineBytes = 64 * 1024
	defaultMaxArrayElems  = 1024
	defaultMaxCommandSize = 4 * 1024 * 1024
	defaultMaxClients     = 1024
	defaultMaxClientsIP   = 16
	defaultMaxReplyBytes  = 64 << 20
	defaultReplicaTTL     = 30 * time.Minute

	// writeTimeout bounds every reply write.
	writeTimeout = 10 * time.Second
	// largeReplyBytes is the size from which a reply counts against
	// MaxReplyBytes; smaller replies are never refused.
	largeReplyBytes = 64 * 1024

	maxAcceptBackoff = time.Second

	HealthcheckClientName = "__redishoneypot_healthcheck__"
)

type ServerOptions struct {
	Address        string
	Network        string
	Profile        RedisProfile
	IdleTimeout    time.Duration
	MaxBulkBytes   int
	MaxInlineBytes int
	MaxArrayElems  int
	// MaxCommandBytes caps the summed bulk payload of a single command.
	MaxCommandBytes int
	MaxClients      int
	// MaxClientsPerIP caps the open connections of one source address;
	// 0 means the default, a negative value no limit.
	MaxClientsPerIP int
	// MaxDataBytes caps keys, cached scripts and config values together;
	// writes above it get Redis' OOM error. 0 means the default.
	MaxDataBytes int64
	// MaxReplyBytes caps the large replies all connections hold at once; a
	// connection whose reply does not fit is closed, like Redis' output
	// buffer limit. 0 means the default.
	MaxReplyBytes int64
	// ReplicaStateTTL is how long the master set by SLAVEOF / REPLICAOF is
	// remembered for its source address after its last such command.
	ReplicaStateTTL time.Duration
	// MaxLoggedPayloadBytes caps value_text, script_text and config_value.
	MaxLoggedPayloadBytes int
	Logger                *slog.Logger
	// TrustedPeer decides whether a peer may use the healthcheck client name to
	// suppress session logs. Defaults to loopback peers only.
	TrustedPeer func(net.Addr) bool
}

type RedisServer struct {
	listener net.Listener
	store    *Store
	profile  RedisProfile
	runtime  *runtimeFingerprint
	logger   *slog.Logger
	options  ServerOptions

	startedAt time.Time
	done      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	configMu       sync.RWMutex
	config         map[string]string
	configDefaults map[string]string

	replMu   sync.Mutex
	replicas map[string]*replicationState

	budget      *memBudget
	replyBytes  atomic.Int64
	refusedMu   sync.Mutex
	refusedLogs map[string]*refusedLog

	stats   *serverStats
	scripts *scriptCache

	// clientsByIP counts open sessions per remote IP for connected_clients;
	// guarded by connMu.
	clientsByIP map[string]int

	totalConnections atomic.Uint64
	totalCommands    atomic.Uint64
	keyspaceHits     atomic.Uint64
	keyspaceMisses   atomic.Uint64
	protocolErrors   atomic.Uint64
	rejectedConns    atomic.Uint64
	syncFull         atomic.Uint64
	netIn            atomic.Uint64
	netOut           atomic.Uint64
	activeClients    atomic.Int64
	clientIDs        atomic.Uint64
}

type clientState struct {
	id            uint64
	sessionID     string
	db            int
	name          string
	libName       string
	libVersion    string
	connected     time.Time
	connectLogged bool
	suppressLogs  bool
	trustedLocal  bool

	proto      int
	remoteIP   string
	remoteAddr string
	localAddr  string
	fd         int
	netIn      int64
	netOut     int64
	commands   int64
	replica    bool

	// writeTargetSet is set once CONFIG SET dir/dbfilename succeeded.
	writeTargetSet bool
	hints          []string
}

func (s *clientState) addHint(hint string) {
	for _, existing := range s.hints {
		if existing == hint {
			return
		}
	}
	if len(s.hints) < 32 {
		s.hints = append(s.hints, hint)
	}
}

func DefaultServerOptions() ServerOptions {
	profile, _ := LookupRedisProfile(DefaultProfileName)
	return ServerOptions{
		Address:               "0.0.0.0:6379",
		Network:               "tcp",
		Profile:               profile,
		IdleTimeout:           defaultIdleTimeout,
		MaxBulkBytes:          defaultMaxBulkBytes,
		MaxInlineBytes:        defaultMaxInlineBytes,
		MaxArrayElems:         defaultMaxArrayElems,
		MaxCommandBytes:       defaultMaxCommandSize,
		MaxClients:            defaultMaxClients,
		MaxClientsPerIP:       defaultMaxClientsIP,
		MaxDataBytes:          defaultMaxDataBytes,
		MaxReplyBytes:         defaultMaxReplyBytes,
		ReplicaStateTTL:       defaultReplicaTTL,
		MaxLoggedPayloadBytes: defaultMaxLoggedPayloadBytes,
		Logger:                NewJSONLogger(os.Stdout),
		TrustedPeer:           isLoopbackPeer,
	}
}

func NewRedisServer(address string, proto string, _ int) (*RedisServer, error) {
	options := DefaultServerOptions()
	options.Address = address
	options.Network = proto
	return NewRedisServerWithOptions(options)
}

func NewRedisServerWithOptions(options ServerOptions) (*RedisServer, error) {
	if options.Address == "" {
		options.Address = "0.0.0.0:6379"
	}
	if options.Network == "" {
		options.Network = "tcp"
	}
	if options.Profile.Name == "" {
		profile, _ := LookupRedisProfile(DefaultProfileName)
		options.Profile = profile
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = defaultIdleTimeout
	}
	if options.MaxBulkBytes <= 0 {
		options.MaxBulkBytes = defaultMaxBulkBytes
	}
	if options.MaxInlineBytes <= 0 {
		options.MaxInlineBytes = defaultMaxInlineBytes
	}
	if options.MaxArrayElems <= 0 {
		options.MaxArrayElems = defaultMaxArrayElems
	}
	if options.MaxCommandBytes <= 0 {
		options.MaxCommandBytes = defaultMaxCommandSize
	}
	if options.MaxClients <= 0 {
		options.MaxClients = defaultMaxClients
	}
	if options.MaxClientsPerIP == 0 {
		options.MaxClientsPerIP = defaultMaxClientsIP
	}
	if options.MaxDataBytes <= 0 {
		options.MaxDataBytes = defaultMaxDataBytes
	}
	if options.MaxReplyBytes <= 0 {
		options.MaxReplyBytes = defaultMaxReplyBytes
	}
	if options.ReplicaStateTTL <= 0 {
		options.ReplicaStateTTL = defaultReplicaTTL
	}
	if options.MaxLoggedPayloadBytes <= 0 {
		options.MaxLoggedPayloadBytes = defaultMaxLoggedPayloadBytes
	}
	if options.Logger == nil {
		options.Logger = NewJSONLogger(os.Stdout)
	}
	if options.TrustedPeer == nil {
		options.TrustedPeer = isLoopbackPeer
	}

	listener, err := net.Listen(options.Network, options.Address)
	if err != nil {
		return nil, err
	}

	budget := newMemBudget(options.MaxDataBytes)
	s := &RedisServer{
		listener:       listener,
		store:          newStoreWithBudget(budget),
		budget:         budget,
		replicas:       make(map[string]*replicationState),
		refusedLogs:    make(map[string]*refusedLog),
		profile:        options.Profile,
		runtime:        newRuntimeFingerprint(options.Profile),
		logger:         options.Logger,
		options:        options,
		startedAt:      time.Now(),
		done:           make(chan struct{}),
		conns:          make(map[net.Conn]struct{}),
		config:         personaConfig(options.Profile),
		configDefaults: personaConfig(options.Profile),
		stats:          newServerStats(),
		scripts:        newScriptCacheWithBudget(budget),
		clientsByIP:    make(map[string]int),
	}
	return s, nil
}

// Start serves connections until Stop is called. It returns only after all
// connection handlers have finished, so callers may close log sinks afterwards.
func (s *RedisServer) Start() error {
	var backoff time.Duration
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				s.wg.Wait()
				return nil
			default:
			}
			if isTemporaryAcceptError(err) {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else {
					backoff *= 2
				}
				if backoff > maxAcceptBackoff {
					backoff = maxAcceptBackoff
				}
				select {
				case <-time.After(backoff):
				case <-s.done:
				}
				continue
			}
			return err
		}
		backoff = 0

		fd, refused, accepted := s.trackConn(conn)
		if !accepted {
			if refused != "" {
				s.rejectedConns.Add(1)
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write(ErrorReply("ERR max number of clients reached").Bytes())
				s.logRefused(conn, refused)
			}
			_ = conn.Close()
			continue
		}
		go s.handleConn(conn, fd)
	}
}

func (s *RedisServer) Stop() {
	s.stopOnce.Do(func() {
		s.connMu.Lock()
		close(s.done)
		s.connMu.Unlock()
		_ = s.listener.Close()

		s.connMu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.connMu.Unlock()

		s.wg.Wait()
	})
}

func (s *RedisServer) Addr() net.Addr {
	return s.listener.Addr()
}

// trackConn registers conn and its handler goroutine. It refuses connections
// once Stop has begun, and names the limit (max_clients or
// max_clients_per_ip) when one is reached. fd is the file descriptor Redis
// would show for the connection: after its listening and internal ones.
func (s *RedisServer) trackConn(conn net.Conn) (fd int, refused string, accepted bool) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	select {
	case <-s.done:
		return 0, "", false
	default:
	}
	if len(s.conns) >= s.options.MaxClients {
		return 0, "max_clients", false
	}
	ip := peerIP(conn.RemoteAddr())
	if limit := s.options.MaxClientsPerIP; limit > 0 && s.clientsByIP[ip] >= limit {
		return 0, "max_clients_per_ip", false
	}
	fd = 8 + len(s.conns)
	s.conns[conn] = struct{}{}
	s.clientsByIP[ip]++
	s.wg.Add(1)
	return fd, "", true
}

func (s *RedisServer) removeConn(conn net.Conn) {
	s.connMu.Lock()
	delete(s.conns, conn)
	ip := peerIP(conn.RemoteAddr())
	if s.clientsByIP[ip]--; s.clientsByIP[ip] <= 0 {
		delete(s.clientsByIP, ip)
	}
	s.connMu.Unlock()
}

func peerIP(addr net.Addr) string {
	host, _ := splitAddr(addr)
	return host
}

func isTemporaryAcceptError(err error) bool {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isConnectionGone reports read errors that mean the peer went away or idled
// out; real Redis closes these connections without a protocol error reply.
func isConnectionGone(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

func isLoopbackPeer(addr net.Addr) bool {
	tcpAddr, ok := addr.(*net.TCPAddr)
	return ok && tcpAddr.IP.IsLoopback()
}

func (s *RedisServer) handleConn(conn net.Conn, fd int) {
	defer s.wg.Done()
	defer s.removeConn(conn)
	defer conn.Close()

	state := &clientState{
		id:           s.clientIDs.Add(1),
		sessionID:    randomHex(32),
		connected:    time.Now(),
		trustedLocal: s.options.TrustedPeer(conn.RemoteAddr()),
		proto:        2,
		remoteIP:     peerIP(conn.RemoteAddr()),
		remoteAddr:   conn.RemoteAddr().String(),
		localAddr:    conn.LocalAddr().String(),
		fd:           fd,
	}
	s.totalConnections.Add(1)
	s.activeClients.Add(1)
	defer s.activeClients.Add(-1)

	reader := bufio.NewReader(conn)
	parserConfig := ParserConfig{
		MaxBulkBytes:    s.options.MaxBulkBytes,
		MaxInlineBytes:  s.options.MaxInlineBytes,
		MaxArrayElems:   s.options.MaxArrayElems,
		MaxCommandBytes: s.options.MaxCommandBytes,
	}

	for {
		if s.options.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.options.IdleTimeout))
		}

		args, err := ReadCommand(reader, parserConfig)
		if err != nil {
			if isConnectionGone(err) {
				break
			}
			if errors.Is(err, errEmptyCommand) {
				continue
			}

			s.protocolErrors.Add(1)
			if !state.suppressLogs {
				s.ensureConnectLogged(state, conn)
				s.logProtocolError(state, conn, err)
			}
			reply := ErrorReply("ERR Protocol error: " + err.Error())
			s.stats.record("", 0, reply, false)
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, _ = conn.Write(reply.Bytes())
			break
		}
		if len(args) == 0 {
			continue
		}

		started := time.Now()
		result := s.handleCommand(state, args)
		elapsed := time.Since(started).Microseconds()

		reserved := result.reserved
		if !result.silent && !result.noReply && reserved == 0 {
			if size := result.reply.approxSize(); size >= largeReplyBytes {
				if s.reserveReply(size) {
					reserved = size
				} else {
					// Like Redis' output buffer limit: no reply, the
					// connection is closed.
					result.silent, result.close, result.replyLimited = true, true, true
				}
			}
		}
		var reply []byte
		if !result.silent && !result.noReply {
			reply = result.reply.Encode(state.proto)
		}
		if result.silent {
			result.reply = RawReply("")
		}

		requestBytes := requestSize(args)
		state.netIn += requestBytes
		state.netOut += int64(len(reply))
		state.commands++
		s.netIn.Add(uint64(requestBytes))
		s.netOut.Add(uint64(len(reply)))
		if !state.suppressLogs {
			if !result.rejected && !result.silent {
				s.totalCommands.Add(1)
			}
			s.stats.record(result.statName, elapsed, result.reply, result.rejected)
		}

		var writeErr error
		if len(reply) > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, writeErr = conn.Write(reply)
		}
		s.releaseReply(reserved)
		if writeErr != nil {
			break
		}

		if !state.suppressLogs {
			s.ensureConnectLogged(state, conn)
			s.logCommand(state, conn, args, result, len(reply))
		}

		if result.close {
			break
		}
	}

	if !state.suppressLogs {
		s.ensureConnectLogged(state, conn)
		s.logClose(state, conn, time.Now())
	}
}

// reserveReply counts size against MaxReplyBytes; it fails when the replies
// in flight would exceed it.
func (s *RedisServer) reserveReply(size int64) bool {
	for {
		used := s.replyBytes.Load()
		if used+size > s.options.MaxReplyBytes {
			return false
		}
		if s.replyBytes.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

func (s *RedisServer) releaseReply(size int64) {
	if size > 0 {
		s.replyBytes.Add(-size)
	}
}

func (s *RedisServer) ensureConnectLogged(state *clientState, conn net.Conn) {
	if state.connectLogged {
		return
	}
	s.logConnect(state, conn)
	state.connectLogged = true
}

// personaConfig starts from the CONFIG GET * defaults recorded from the real
// server and applies the persona's deployment overrides for known keys.
func personaConfig(profile RedisProfile) map[string]string {
	config := make(map[string]string, len(profile.data.config))
	for key, value := range profile.data.config {
		config[key] = value
	}
	for key, value := range profile.ConfigOverrides {
		if _, known := config[key]; known {
			config[key] = value
		}
	}
	return config
}

func (s *RedisServer) clientsFrom(ip string) int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if n := s.clientsByIP[ip]; n > 0 {
		return n
	}
	return 1
}

// requestSize is len(encodeRequest(args)) without building the copy.
func requestSize(args []string) int64 {
	size := int64(1 + len(strconv.Itoa(len(args))) + 2)
	for _, arg := range args {
		size += int64(1 + len(strconv.Itoa(len(arg))) + 2 + len(arg) + 2)
	}
	return size
}

func encodeRequest(args []string) []byte {
	values := make([]RESPValue, 0, len(args))
	for _, arg := range args {
		values = append(values, BulkString(arg))
	}
	return Array(values...).Bytes()
}

func (s *clientState) userAgent() string {
	if s.libName == "" {
		return ""
	}
	if s.libVersion == "" {
		return s.libName
	}
	return s.libName + "/" + s.libVersion
}
