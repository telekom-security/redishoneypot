package honeypot

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// handleInfo renders INFO from the persona's recorded template. Field names,
// order and static values come from a real server; values that change at
// runtime or identify a deployment are substituted.
func (s *RedisServer) handleInfo(state *clientState, args []string) RESPValue {
	if len(args) > 1 && !s.profile.atLeast(7, 0) {
		return syntaxError
	}
	data := s.profile.data

	wanted := make(map[string]bool)
	if len(args) == 0 {
		args = []string{"default"}
	}
	for _, arg := range args {
		name := strings.ToLower(arg)
		if group, ok := data.infoGroups[name]; ok && (name == "default" || name == "all" || name == "everything") {
			for section := range group {
				wanted[section] = true
			}
			continue
		}
		wanted[name] = true
	}

	values := s.infoValues(state)
	var out strings.Builder
	for _, section := range data.info {
		key := strings.ToLower(section.name)
		if !wanted[key] {
			continue
		}
		if out.Len() > 0 {
			out.WriteString("\r\n")
		}
		out.WriteString("# ")
		out.WriteString(section.name)
		out.WriteString("\r\n")
		for _, line := range s.infoSectionLines(state, section, values) {
			out.WriteString(line)
			out.WriteString("\r\n")
		}
	}
	return VerbatimText(out.String())
}

func (s *RedisServer) infoSectionLines(state *clientState, section infoSection, values map[string]string) []string {
	switch strings.ToLower(section.name) {
	case "keyspace":
		return s.keyspaceLines()
	case "keysizes":
		return s.keysizesLines()
	case "commandstats":
		return s.commandstatsLines()
	case "errorstats":
		return s.errorstatsLines()
	case "latencystats":
		return s.latencystatsLines()
	case "replication":
		if repl, replica := s.replication(state); replica {
			return s.replicaLines(section, values, repl)
		}
	}

	lines := make([]string, 0, len(section.lines))
	for _, line := range section.lines {
		value := line.value
		if dynamic, ok := values[line.key]; ok {
			value = dynamic
		}
		lines = append(lines, line.key+":"+value)
	}
	return lines
}

func (s *RedisServer) infoValues(state *clientState) map[string]string {
	fp := s.runtime
	profile := s.profile
	now := time.Now()
	uptime := int64(now.Sub(s.startedAt).Seconds())
	if uptime < 0 {
		uptime = 0
	}
	port := 6379
	if tcpAddr, ok := s.listener.Addr().(*net.TCPAddr); ok {
		port = tcpAddr.Port
	}

	usedMemory, rss, peak := fp.memory(s.shownDataBytes())
	peakPercent := 100.0
	if peak > 0 {
		peakPercent = float64(usedMemory) / float64(peak) * 100
	}
	fragmentation := 1.0
	if usedMemory > 0 {
		fragmentation = float64(rss) / float64(usedMemory)
	}
	maxmemory, _ := strconv.ParseInt(s.configValue("maxmemory"), 10, 64)
	_, _, totalErrors := s.stats.snapshot()
	commands := s.totalCommands.Load()
	clients := s.clientsFrom(state.remoteIP)

	values := map[string]string{
		"redis_build_id":                  fp.redisBuildID,
		"os":                              fp.os,
		"process_id":                      strconv.Itoa(fp.processID),
		"process_supervised":              profile.ProcessSupervised,
		"run_id":                          fp.runID,
		"tcp_port":                        strconv.Itoa(port),
		"server_time_usec":                strconv.FormatInt(now.UnixMicro(), 10),
		"uptime_in_seconds":               strconv.FormatInt(uptime, 10),
		"uptime_in_days":                  strconv.FormatInt(uptime/86400, 10),
		"lru_clock":                       strconv.FormatInt(fp.lruClock(uptime), 10),
		"executable":                      profile.Executable,
		"config_file":                     profile.ConfigFile,
		"listener0":                       fmt.Sprintf("name=tcp,bind=*,bind=-::*,port=%d", port),
		"connected_clients":               strconv.Itoa(clients),
		"client_recent_max_input_buffer":  strconv.FormatInt(fp.clientRecentMaxInputBuffer, 10),
		"client_recent_max_output_buffer": strconv.FormatInt(fp.clientRecentMaxOutputBuffer, 10),
		"used_memory":                     strconv.FormatInt(usedMemory, 10),
		"used_memory_human":               formatRedisBytes(usedMemory),
		"used_memory_rss":                 strconv.FormatInt(rss, 10),
		"used_memory_rss_human":           formatRedisBytes(rss),
		"used_memory_peak":                strconv.FormatInt(peak, 10),
		"used_memory_peak_human":          formatRedisBytes(peak),
		"used_memory_peak_perc":           fmt.Sprintf("%.2f%%", peakPercent),
		"total_system_memory":             strconv.FormatInt(fp.totalSystemMemory, 10),
		"total_system_memory_human":       formatRedisBytes(fp.totalSystemMemory),
		"maxmemory":                       strconv.FormatInt(maxmemory, 10),
		"maxmemory_human":                 formatRedisBytes(maxmemory),
		"maxmemory_policy":                s.configValue("maxmemory-policy"),
		"mem_fragmentation_ratio":         fmt.Sprintf("%.2f", fragmentation),
		"mem_fragmentation_bytes":         strconv.FormatInt(rss-usedMemory, 10),
		"number_of_cached_scripts":        strconv.Itoa(s.scripts.count()),
		"rdb_changes_since_last_save":     strconv.FormatInt(fp.rdbChangesSinceSave.Load(), 10),
		"rdb_last_save_time":              strconv.FormatInt(fp.rdbLastSaveTime.Load(), 10),
		"rdb_last_bgsave_time_sec":        strconv.FormatInt(fp.rdbLastBgsaveTimeSec.Load(), 10),
		"rdb_saves":                       strconv.FormatInt(fp.rdbSaves.Load(), 10),
		"total_forks":                     strconv.FormatInt(fp.rdbSaves.Load(), 10),
		"latest_fork_usec":                strconv.FormatInt(fp.latestForkUsec, 10),
		"total_connections_received":      strconv.FormatUint(s.totalConnections.Load(), 10),
		"total_commands_processed":        strconv.FormatUint(commands, 10),
		"total_net_input_bytes":           strconv.FormatUint(s.netIn.Load(), 10),
		"total_net_output_bytes":          strconv.FormatUint(s.netOut.Load(), 10),
		"rejected_connections":            strconv.FormatUint(s.rejectedConns.Load(), 10),
		"sync_full":                       strconv.FormatUint(s.syncFull.Load(), 10),
		"expired_keys":                    strconv.FormatUint(s.store.ExpiredKeys(), 10),
		"keyspace_hits":                   strconv.FormatUint(s.keyspaceHits.Load(), 10),
		"keyspace_misses":                 strconv.FormatUint(s.keyspaceMisses.Load(), 10),
		"total_error_replies":             strconv.FormatUint(totalErrors, 10),
		"total_reads_processed":           strconv.FormatUint(commands+s.totalConnections.Load(), 10),
		"total_writes_processed":          strconv.FormatUint(commands, 10),
		"master_replid":                   fp.masterReplID,
		"used_cpu_sys":                    fmt.Sprintf("%.6f", fp.cpuSys(uptime)),
		"used_cpu_user":                   fmt.Sprintf("%.6f", fp.cpuUser(uptime)),
		"used_cpu_sys_children":           fmt.Sprintf("%.6f", fp.cpuSysChildrenBase),
		"used_cpu_user_children":          fmt.Sprintf("%.6f", fp.cpuUserChildrenBase),
		"used_cpu_sys_main_thread":        fmt.Sprintf("%.6f", fp.cpuSys(uptime)*0.92),
		"used_cpu_user_main_thread":       fmt.Sprintf("%.6f", fp.cpuUser(uptime)*0.95),
		"io_thread_0":                     fmt.Sprintf("clients=%d,reads=%d,writes=%d", clients, commands+s.totalConnections.Load(), commands),
	}
	if fp.monotonicClock != "" {
		values["monotonic_clock"] = fp.monotonicClock
	}
	if profile.GCCVersion != "" {
		values["gcc_version"] = profile.GCCVersion
	}
	return values
}

func (s *RedisServer) keyspaceLines() []string {
	keyspace := s.store.Keyspace()
	dbs := make([]int, 0, len(keyspace))
	for db := range keyspace {
		dbs = append(dbs, db)
	}
	sort.Ints(dbs)
	subexpiry := !s.profile.isValkey() && s.profile.atLeast(7, 4)
	lines := make([]string, 0, len(dbs))
	for _, db := range dbs {
		line := fmt.Sprintf("db%d:keys=%d,expires=%d,avg_ttl=0", db, keyspace[db].keys, keyspace[db].expires)
		if subexpiry {
			line += ",subexpiry=0"
		}
		lines = append(lines, line)
	}
	return lines
}

// keysizesLines renders Redis 8's power-of-two string length histogram.
func (s *RedisServer) keysizesLines() []string {
	histogram := s.store.SizeHistogram()
	dbs := make([]int, 0, len(histogram))
	for db := range histogram {
		dbs = append(dbs, db)
	}
	sort.Ints(dbs)
	var lines []string
	for _, db := range dbs {
		buckets := histogram[db]
		keys := make([]int64, 0, len(buckets))
		for bucket := range buckets {
			keys = append(keys, bucket)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		parts := make([]string, 0, len(keys))
		for _, bucket := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", humanPowerOfTwo(bucket), buckets[bucket]))
		}
		lines = append(lines, fmt.Sprintf("db%d_distrib_strings_sizes:%s", db, strings.Join(parts, ",")))
	}
	return lines
}

func humanPowerOfTwo(n int64) string {
	for _, unit := range []struct {
		suffix string
		size   int64
	}{{"P", 1 << 50}, {"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}} {
		if n >= unit.size && n%unit.size == 0 {
			return strconv.FormatInt(n/unit.size, 10) + unit.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}

func (s *RedisServer) commandstatsLines() []string {
	commands, _, _ := s.stats.snapshot()
	lines := make([]string, 0, len(commands))
	for _, stat := range commands {
		if stat.calls == 0 && stat.rejected == 0 {
			continue
		}
		perCall := 0.0
		if stat.calls > 0 {
			perCall = float64(stat.usec) / float64(stat.calls)
		}
		line := fmt.Sprintf("cmdstat_%s:calls=%d,usec=%d,usec_per_call=%.2f", stat.name, stat.calls, stat.usec, perCall)
		if s.profile.atLeast(6, 2) {
			line += fmt.Sprintf(",rejected_calls=%d,failed_calls=%d", stat.rejected, stat.failed)
		}
		lines = append(lines, line)
	}
	return lines
}

func (s *RedisServer) errorstatsLines() []string {
	_, errors, _ := s.stats.snapshot()
	prefixes := make([]string, 0, len(errors))
	for prefix := range errors {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	lines := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		lines = append(lines, fmt.Sprintf("errorstat_%s:count=%d", prefix, errors[prefix]))
	}
	return lines
}

func (s *RedisServer) latencystatsLines() []string {
	commands, _, _ := s.stats.snapshot()
	lines := make([]string, 0, len(commands))
	for _, stat := range commands {
		if stat.calls == 0 {
			continue
		}
		perCall := float64(stat.usec) / float64(stat.calls)
		lines = append(lines, fmt.Sprintf("latency_percentiles_usec_%s:p50=%.3f,p99=%.3f,p99.9=%.3f",
			stat.name, perCall*0.9, perCall*1.1, perCall*1.15))
	}
	return lines
}

// replicaLines turns the recorded master section into what a replica with an
// unreachable master reports.
func (s *RedisServer) replicaLines(section infoSection, values map[string]string, repl replicationState) []string {
	downSince := int64(time.Since(repl.since).Seconds())
	replicaFields := []string{
		"role:slave",
		"master_host:" + repl.masterHost,
		"master_port:" + strconv.Itoa(repl.masterPort),
		"master_link_status:down",
		"master_last_io_seconds_ago:-1",
		"master_sync_in_progress:0",
	}
	if s.profile.atLeast(6, 2) {
		replicaFields = append(replicaFields, "slave_read_repl_offset:0")
	}
	replicaFields = append(replicaFields,
		"slave_repl_offset:0",
		"master_link_down_since_seconds:"+strconv.FormatInt(downSince, 10),
		"slave_priority:100",
		"slave_read_only:1",
	)
	if s.profile.atLeast(6, 2) {
		replicaFields = append(replicaFields, "replica_announced:1")
	}

	lines := append([]string(nil), replicaFields...)
	for _, line := range section.lines {
		if line.key == "role" {
			continue
		}
		value := line.value
		if dynamic, ok := values[line.key]; ok {
			value = dynamic
		}
		lines = append(lines, line.key+":"+value)
	}
	return lines
}
