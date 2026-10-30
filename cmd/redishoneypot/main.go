package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"RedisHoneyPot/internal/honeypot"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(os.Args[2:]))
	}

	options := honeypot.DefaultServerOptions()
	var legacyLoops int
	var profileName string
	var logFilePath string
	var logStdout bool

	flag.StringVar(&options.Address, "addr", options.Address, "listen address")
	flag.StringVar(&options.Network, "proto", options.Network, "listen protocol")
	flag.IntVar(&legacyLoops, "num", 1, "deprecated compatibility flag; ignored")
	flag.StringVar(&profileName, "profile", honeypot.DefaultProfileName, "server persona: "+strings.Join(honeypot.ProfileNames(), ", "))
	flag.DurationVar(&options.IdleTimeout, "idle-timeout", options.IdleTimeout, "connection idle timeout")
	flag.IntVar(&options.MaxBulkBytes, "max-bulk-bytes", options.MaxBulkBytes, "maximum RESP bulk string size")
	flag.IntVar(&options.MaxCommandBytes, "max-command-bytes", options.MaxCommandBytes, "maximum summed bulk payload of one command")
	flag.IntVar(&options.MaxClients, "max-clients", options.MaxClients, "maximum concurrent client connections")
	flag.IntVar(&options.MaxClientsPerIP, "max-clients-per-ip", options.MaxClientsPerIP, "maximum concurrent connections of one source address (negative: no limit)")
	flag.Int64Var(&options.MaxDataBytes, "max-data-bytes", options.MaxDataBytes, "maximum bytes of keys, cached scripts and CONFIG values; writes above it get an OOM error")
	flag.Int64Var(&options.MaxReplyBytes, "max-reply-bytes", options.MaxReplyBytes, "maximum bytes of large replies held at once; a connection over it is closed")
	flag.DurationVar(&options.ReplicaStateTTL, "replica-state-ttl", options.ReplicaStateTTL, "how long a source address keeps the master it set with SLAVEOF / REPLICAOF")
	flag.IntVar(&options.MaxLoggedPayloadBytes, "max-logged-payload-bytes", options.MaxLoggedPayloadBytes, "maximum bytes of SET values, scripts and CONFIG values in logs")
	flag.StringVar(&logFilePath, "log-file", "", "optional JSONL honeypot event log file")
	flag.BoolVar(&logStdout, "log-stdout", true, "also write honeypot events to stdout when -log-file is set")
	flag.Parse()

	appLogger := honeypot.NewJSONLogger(os.Stdout)
	profile, ok := honeypot.LookupRedisProfile(profileName)
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "unknown profile %q; expected one of %s\n", profileName, strings.Join(honeypot.ProfileNames(), ", "))
		os.Exit(2)
	}
	options.Profile = profile
	if logFilePath == "" && !logStdout {
		_, _ = fmt.Fprintln(os.Stderr, "-log-stdout=false needs -log-file, honeypot events would go nowhere")
		os.Exit(2)
	}

	var logFile io.Writer
	if logFilePath != "" {
		if err := os.MkdirAll(filepath.Dir(logFilePath), 0o750); err != nil {
			appLogger.Error("log_file_setup_failed", "event", "log_file_setup_failed", "path", logFilePath, "error", err)
			os.Exit(1)
		}

		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			appLogger.Error("log_file_open_failed", "event", "log_file_open_failed", "path", logFilePath, "error", err)
			os.Exit(1)
		}
		defer file.Close()
		logFile = file
	}
	options.Logger = honeypot.NewJSONLogger(eventWriter(os.Stdout, logFile, logStdout))

	server, err := honeypot.NewRedisServerWithOptions(options)
	if err != nil {
		appLogger.Error("startup_failed", "event", "startup_failed", "error", err)
		os.Exit(1)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		appLogger.Info("shutdown_requested", "event", "shutdown_requested")
		server.Stop()
	}()

	if legacyLoops != 1 {
		appLogger.Warn("deprecated_flag_ignored", "event", "deprecated_flag_ignored", "flag", "num", "value", legacyLoops)
	}
	startAttrs := []any{
		"event", "start",
		"addr", server.Addr().String(),
		"network", options.Network,
		"profile", options.Profile.Name,
		"idle_timeout", options.IdleTimeout.String(),
		"max_bulk_bytes", options.MaxBulkBytes,
		"max_command_bytes", options.MaxCommandBytes,
		"max_clients", options.MaxClients,
		"max_clients_per_ip", options.MaxClientsPerIP,
		"max_data_bytes", options.MaxDataBytes,
		"max_reply_bytes", options.MaxReplyBytes,
		"replica_state_ttl", options.ReplicaStateTTL.String(),
		"max_logged_payload_bytes", options.MaxLoggedPayloadBytes,
	}
	if logFilePath != "" {
		startAttrs = append(startAttrs, "log_file", logFilePath, "log_stdout", logStdout)
	}
	appLogger.Info("start", startAttrs...)

	// Start returns only after every connection handler has written its close
	// event, so the deferred log file close cannot drop session events.
	if err := server.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
		appLogger.Error("server_failed", "event", "server_failed", "error", err)
		os.Exit(1)
	}
}

// eventWriter returns where honeypot events go: stdout, the log file, or both.
// Process lifecycle events always stay on stdout. A nil file means stdout,
// main refuses -log-stdout=false without -log-file.
func eventWriter(stdout io.Writer, file io.Writer, logStdout bool) io.Writer {
	switch {
	case file == nil:
		return stdout
	case logStdout:
		return io.MultiWriter(stdout, file)
	default:
		return file
	}
}
