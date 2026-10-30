package honeypot

import (
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strings"
)

const maxIOCsPerKind = 16

var (
	urlPattern  = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://[^\s'"<>\\]+`)
	ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// iocAttrs extracts URLs, IPv4 addresses and URL host names from command
// arguments as space-separated strings, so flat-log consumers such as
// ewsposter can forward them without arrays.
func iocAttrs(args []string) []slog.Attr {
	if len(args) == 0 {
		return nil
	}
	text := strings.Join(args, " ")

	var urls, ips, domains []string
	seen := map[string]bool{}
	truncated := false
	add := func(list *[]string, value string) {
		if value == "" || len(*list) >= maxIOCsPerKind {
			return
		}
		// An entry is cut like any other attacker field.
		value, cut := capString(value, maxLoggedFieldBytes)
		if seen[value] {
			return
		}
		seen[value] = true
		truncated = truncated || cut
		*list = append(*list, value)
	}

	for _, raw := range urlPattern.FindAllString(text, -1) {
		raw = strings.TrimRight(raw, ".,;)|&")
		add(&urls, raw)
		if parsed, err := url.Parse(raw); err == nil {
			host := parsed.Hostname()
			if net.ParseIP(host) == nil {
				add(&domains, strings.ToLower(host))
			}
		}
	}
	for _, candidate := range ipv4Pattern.FindAllString(text, -1) {
		if ip := net.ParseIP(candidate); ip != nil && ip.To4() != nil {
			add(&ips, candidate)
		}
	}

	var attrs []slog.Attr
	if len(urls) > 0 {
		attrs = append(attrs, slog.String("ioc_urls", strings.Join(urls, " ")))
	}
	if len(ips) > 0 {
		attrs = append(attrs, slog.String("ioc_ips", strings.Join(ips, " ")))
	}
	if len(domains) > 0 {
		attrs = append(attrs, slog.String("ioc_domains", strings.Join(domains, " ")))
	}
	if count := len(urls) + len(ips) + len(domains); count > 0 {
		attrs = append(attrs, slog.Int("ioc_count", count))
	}
	if truncated {
		attrs = append(attrs, slog.Bool("ioc_truncated", true))
	}
	return attrs
}
