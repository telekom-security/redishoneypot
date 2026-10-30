# RedisHoneyPot

RedisHoneyPot is a high-interaction Redis protocol honeypot written in Go. It is designed to look useful to opportunistic Redis scanners and common post-exploitation playbooks while keeping all behavior local and non-executing.

This service is intentionally deceptive. Run it only in an isolated monitoring environment, keep host permissions minimal, and block outbound traffic so attacker-triggered replication or module-loading attempts cannot leave the sensor.

## Features

- RESP2 and RESP3 (`HELLO 3`) server implemented with the Go standard library.
- Data-driven personas recorded from real servers (see [Personas](#personas)):
  `redis74` (default), `legacy6`, `current8`, `redis50`, `valkey8`.
- Replies match the real versions byte for byte where it matters to scanners:
  error texts, `COMMAND`/`COMMAND DOCS`, `INFO` field layout, `CONFIG GET *`,
  `CLIENT LIST`, `HELLO`, protocol errors and silent close on HTTP requests.
- Per-start variation of identifying values (kernel string, memory size,
  build id, run id, replication id, CPU and memory counters).
- File-write playbooks (`CONFIG SET dir/dbfilename` + `SET` + `SAVE`) proceed;
  `EVAL`/`SCRIPT`/`FUNCTION` answer without running Lua; `SLAVEOF` turns the
  server into a read-only replica with a down link; `PSYNC` sends a valid RDB.
- Flat JSON logs with full payload capture, IOC extraction and analysis hints.
- Bounded by design: every log field and line is capped, data, cached scripts
  and replies have byte budgets, and one source address gets a limited number
  of connections (see [Limits](#limits)).
- Nothing is executed, written to disk or connected to: all state is in memory.

## Build

```sh
GOTOOLCHAIN=go1.27.2 go build -o RedisHoneyPot ./cmd/redishoneypot
```

## Run

```sh
./RedisHoneyPot -addr 0.0.0.0:6379 -proto tcp -profile redis74
```

Useful flags:

```text
-addr                      Listen address. Default: 0.0.0.0:6379
-proto                     Listen protocol. Default: tcp
-profile                   Persona: redis74, legacy6, current8, redis50, valkey8. Default: redis74
-idle-timeout              Connection idle timeout. Default: 5m
-max-bulk-bytes            Maximum RESP bulk string size. Default: 1048576
-max-command-bytes         Maximum summed bulk payload of one command. Default: 4194304
-max-clients               Maximum concurrent connections. Default: 1024
-max-clients-per-ip        Maximum concurrent connections of one source address; negative: no limit. Default: 16
-max-data-bytes            Bytes of keys, cached scripts and CONFIG values; writes above get Redis' OOM error. Default: 67108864
-max-reply-bytes           Bytes of large replies (64 KiB and more) held at once; a connection over it is closed. Default: 67108864
-replica-state-ttl         How long a source address keeps the master it set with SLAVEOF. Default: 30m
-max-logged-payload-bytes  Bytes of SET values, scripts and CONFIG values kept in logs. Default: 8192
-log-file                  Optional JSONL event log file
-log-stdout                Also write honeypot events to stdout when -log-file is set. Default: true
-num                       Deprecated compatibility flag; accepted but ignored
```

## Limits

Worst-case memory is roughly `max-clients × max-command-bytes` for the
parser plus `max-data-bytes` plus `max-reply-bytes`. The Docker image uses
`-max-clients 128 -max-command-bytes 1048576 -max-data-bytes 33554432
-max-reply-bytes 33554432` and `GOMEMLIMIT=200MiB` with a 256 MiB Compose
memory limit. `INFO` keeps reporting the persona's `maxclients:10000`.

- **Connections.** Above `-max-clients`, or above `-max-clients-per-ip` for
  one source address, a new connection gets `-ERR max number of clients
  reached` and is closed. It is logged as a `refused` event with `reason`
  (`max_clients` or `max_clients_per_ip`) and `refused_count`; one source
  address gets at most one such line per minute, `refused_count` includes the
  refusals in between.
- **Data.** Keys count with their key, value and 64 bytes each; cached scripts
  (at most 1024 and 8 MiB, the oldest are dropped) and CONFIG values longer
  than the persona's defaults count too. A `SET` or `CONFIG SET` above
  `-max-data-bytes` gets `-OOM command not allowed when used memory >
  'maxmemory'.`; a script that does not fit is answered but not cached.
  `used_memory` in `INFO` is the persona's idle value plus these bytes.
- **Replies.** A reply of 64 KiB or more (`GET`, `KEYS`, `SYNC` / `PSYNC`, ...)
  counts against `-max-reply-bytes` until it is written. A connection whose
  reply does not fit is closed without a reply, like Redis' output buffer
  limit; its `command` event has `outcome` `connection_closed` and
  `reply_limited`.
- **Client metadata.** The connection keeps at most 4 KiB of `CLIENT SETNAME`,
  `HELLO ... SETNAME` and `CLIENT SETINFO` values; `CLIENT SETINFO` refuses
  spaces, newlines and special characters like Redis 7.2.
- **Replication.** `SLAVEOF` / `REPLICAOF` turn the server into a replica for
  the source address that sent it only, until `SLAVEOF NO ONE` or
  `-replica-state-ttl` after its last `SLAVEOF`. Keys and `CONFIG` stay shared.
- **Writes.** Every reply write has a 10 s deadline.

## Docker

Build the image:

```sh
docker build -t redishoneypot:local .
```

Run it directly:

```sh
docker run --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 6379:6379/tcp \
  redishoneypot:local
```

Run with Docker Compose:

```sh
docker compose up --build
```

Docker Compose bind-mounts `./logs` on the host to `/var/log/redishoneypot` in the container. The image writes honeypot event logs to `/var/log/redishoneypot/redishoneypot.log`, so the host-side file is `logs/redishoneypot.log`.

The container still writes stdout JSON logs, but the mounted event log intentionally contains only honeypot interaction events. Typical process lifecycle events such as `start`, `shutdown_requested`, `startup_failed`, and `server_failed` are kept out of `redishoneypot.log`.

Add `-log-stdout=false` to keep the interaction events in the log file only, so stdout carries the lifecycle events alone. Use it where the container log is not rotated and every event would otherwise be stored twice. Without `-log-file` the flag is refused (exit code 2).

If your host user is not UID/GID `1000`, pass the desired runtime IDs when starting Compose so the non-root container can write to the bind mount:

```sh
REDISHONEYPOT_UID="$(id -u)" REDISHONEYPOT_GID="$(id -g)" docker compose up --build
```

Keep egress filtering at the host, firewall, or orchestration layer if this sensor is exposed to untrusted traffic.

The image includes a built-in Docker healthcheck. It runs:

```sh
/redishoneypot healthcheck -addr 127.0.0.1:6379 -timeout 2s
```

The probe identifies itself with `CLIENT SETNAME __redishoneypot_healthcheck__`. The server suppresses logs for that session only when it comes from a loopback address, so periodic healthchecks do not fill the event stream while remote clients using the same name are still logged.

Smoke-test a running Compose container:

```sh
docker compose up -d --build
./scripts/smoke-running-container.sh
```

The smoke test sends Redis protocol commands through the published port and verifies that the lines it appended to `logs/redishoneypot.log` contain command/session events without lifecycle events or JSON `null` fields. It never truncates the log and restores the key and `dir` it changed, so it is safe against a live sensor.

## Personas

| Persona   | Server             | Layout                                   | Notes |
|-----------|--------------------|------------------------------------------|-------|
| `redis74` | Redis 7.4.5        | Docker (`/data/redis-server`, PID 1)     | Default. `enable-protected-configs yes` and `enable-module-command yes`, so file-write TTPs proceed. |
| `legacy6` | Redis 6.2.18       | Source install (`/usr/local/bin`, `/etc/redis/6379.conf`) | Pre-7 error texts, no `CLIENT SETINFO`, no `COMMAND DOCS`. |
| `current8`| Redis 8.8.0        | Docker with bundled modules              | Real 8.x defaults: protected configs and `MODULE LOAD` are refused. |
| `redis50` | Redis 5.0.7        | Ubuntu 20.04 package                     | No ACL/`HELLO`, old `AUTH` errors. |
| `valkey8` | Valkey 8.1.3       | Docker (`/data/valkey-server`)           | `server_name:valkey`, Valkey-specific replies. |

Each persona is backed by data recorded from the real server in
`internal/honeypot/personas/<name>/`: the `COMMAND` and `COMMAND DOCS` replies,
`CONFIG GET *` defaults, `MODULE LIST`, the `INFO` templates for
`default`/`all`/`everything` and a `CLIENT LIST` line. Arity checks and
subcommand validation use the real command table. `INFO` keeps the real field
order and substitutes runtime values; command, error and latency statistics
reflect actual sessions. Values that would let sensors be clustered (kernel,
total memory, monotonic clock) are drawn per start from plausible candidates.

Commands with real behaviour: `PING ECHO AUTH HELLO QUIT INFO SET GET MGET DEL
EXISTS KEYS SCAN TYPE TTL PTTL EXPIRE PEXPIRE PERSIST SELECT DBSIZE FLUSHDB
FLUSHALL SAVE BGSAVE LASTSAVE CONFIG CLIENT COMMAND ROLE TIME DEBUG MODULE
SLAVEOF REPLICAOF REPLCONF PSYNC SYNC EVAL EVAL_RO EVALSHA EVALSHA_RO SCRIPT
FUNCTION FCALL FCALL_RO`. Other commands the persona knows answer like an
unknown command.

Honeypot semantics:

- `CONFIG SET dir` accepts typical Linux directories (cron spools, `.ssh`
  folders, web roots) and rejects random paths with the real error.
- `SAVE`/`BGSAVE`, `MODULE LOAD`, `SLAVEOF` and `PSYNC` never write files,
  load code or open outbound connections. `MODULE LOAD` fails like a server
  whose module file does not exist.
- Scripts are cached by SHA1 and never executed; literal returns are answered.

### Re-recording persona data

```sh
./scripts/record-fixtures.sh            # all personas, needs Docker
./scripts/record-fixtures.sh redis74    # one persona
```

The script starts loopback-bound containers, runs `cmd/fixture-recorder`
(persona data plus probe replies in `internal/honeypot/testdata/fixtures/`)
and removes the containers. `TestFidelityAgainstRecordedServers` replays the
probes against every persona.

## Logs

Logs are flat JSON lines on stdout. Field names use snake case and values are primitive JSON types only, so Logstash can ingest them without nested object or array mappings. Timestamps use UTC RFC3339Nano, which is ISO-8601 compatible. Fields with unknown or unavailable values are omitted instead of being emitted as JSON `null` or empty placeholders.

Event names include:

```text
start connect command protocol_error close refused shutdown_requested
```

Connection and command events include:

```text
timestamp event message level protocol network profile session_id client_id
src_ip src_port dest_ip dest_port session_start session_duration session_duration_ms
```

`close` events also include `session_end`, `session_command_count` and, when any analysis hint was seen, `session_hints` (space-separated). Client metadata fields such as `client_name`, `client_library_name`, `client_library_version`, and `user_agent` are emitted only after the client has supplied them.

Command events also include:

```text
redis_db command command_category arg_count response_class response_bytes outcome close_after_command
```

Argument fields such as `args_text` (first 512 bytes), `args_truncated`, and `args_sha256` are emitted only when the command has arguments. Additional analysis fields are emitted when relevant:

```text
analysis_hint key key_count key_pattern value_size value_sha256 value_text value_truncated
config_subcommand config_key config_value config_value_truncated config_value_sha256
replica_host replica_port replconf_key replconf_value module_subcommand module_path
auth_username auth_password_length auth_password_sha256 client_subcommand
script_sha1 script_sha256 script_size script_text script_truncated script_numkeys
target_dir target_dbfilename ioc_urls ioc_ips ioc_domains ioc_count
```

`value_text`, `script_text` and `config_value` keep up to `-max-logged-payload-bytes`. Every other field an attacker controls is capped too: `client_name`, `client_library_name` and `client_library_version` at 128 bytes, `user_agent` at 257, `command`, the key, config, replication, module, script, target and auth fields and each IOC entry at 1024 bytes. A cut field gets `<field>_truncated: true` next to it (`ioc_truncated` for the IOC lists). A line is at most 64 KiB; above that the largest fields are dropped and the line gets `log_truncated: true`. `ioc_*` fields are space-separated lists (at most 16 entries each) extracted from all arguments. `script_sha1` matches the SHA1 used by `EVALSHA`, so loads and later calls can be correlated.

`analysis_hint` values include `redis_write_file_attempt`, `redis_write_file_commit` (`SAVE`/`BGSAVE` after the session changed `dir`/`dbfilename`, with `target_dir`/`target_dbfilename`), `redis_save_attempt`, `ssh_key_payload`, `cron_payload`, `redis_replication_attempt`, `redis_module_load_attempt`, `redis_auth_attempt`, `redis_auth_config_attempt`, `redis_lua_eval`, `redis_lua_script_load` and `redis_function_load`. `outcome` is `success`, `error` or `connection_closed` (HTTP requests, which Redis drops silently).

Redis does not have an HTTP-style User-Agent header. The `user_agent` field is populated when a client sends Redis client metadata with `CLIENT SETINFO LIB-NAME ...` and optionally `CLIENT SETINFO LIB-VER ...`; otherwise the field is omitted. Passwords of `AUTH`, `HELLO ... AUTH`, `MIGRATE ... AUTH` / `AUTH2` and `CONFIG SET requirepass` / `masterauth` are redacted from `args_text` and `config_value` while their SHA-256 hashes (and for `AUTH` their lengths) are still logged for correlation.

Example:

```json
{"timestamp":"2026-06-16T12:00:00Z","level":"INFO","message":"command","event":"command","protocol":"redis","network":"tcp","profile":"redis74","session_id":"6f8b1f7a0d9c44b2a78f8ef650d01d2c","client_id":1,"src_ip":"203.0.113.10","src_port":51432,"dest_ip":"198.51.100.20","dest_port":6379,"session_start":"2026-06-16T12:00:00Z","session_duration":1.234,"session_duration_ms":1234,"client_library_name":"go-redis","client_library_version":"9.7.0","user_agent":"go-redis/9.7.0","redis_db":0,"command":"CONFIG","command_category":"recon","arg_count":3,"args_text":"SET dir /tmp","args_truncated":false,"args_sha256":"...","response_class":"simple_string","response_bytes":5,"outcome":"success","close_after_command":false,"analysis_hint":"redis_write_file_attempt","config_subcommand":"set","config_key":"dir","config_value":"/tmp","config_value_truncated":false,"config_value_sha256":"..."}
```

## Tests

```sh
GOTOOLCHAIN=go1.27.2 go test ./...
GOTOOLCHAIN=go1.27.2 go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The test suite covers RESP parsing/encoding, command behavior, fidelity against recorded real-server replies for every persona, logging and payload capture, and TCP smoke tests for redis-cli-like flows.

## Repository Layout

```text
cmd/redishoneypot/          CLI entrypoint and process signal handling
cmd/fixture-recorder/       Records persona data and fixtures from real servers
cmd/container-smoketest/    Smoke test against a running container
internal/honeypot/          Protocol server, personas, parser, store, logging, and tests
internal/honeypot/personas/ Recorded persona data (embedded)
internal/fixtures/          Probe catalogue shared by recorder and tests
scripts/                    Container smoke test and fixture recording
README.md                   Operator documentation
```

## Deployment Notes

- Prefer a dedicated VM, container, or network namespace.
- Do not run with privileged filesystem permissions.
- Apply egress filtering; the honeypot should not be able to connect back to attacker-controlled replication hosts.
- Send stdout logs to your collector and keep raw payload retention aligned with your local policy.
- Put the sensor on infrastructure where receiving unsolicited traffic is expected and authorized.
