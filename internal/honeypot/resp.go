package honeypot

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var errEmptyCommand = errors.New("empty command")

type ParserConfig struct {
	MaxBulkBytes    int
	MaxInlineBytes  int
	MaxArrayElems   int
	MaxCommandBytes int
}

type respKind int

const (
	respSimple respKind = iota
	respError
	respInteger
	respBulk
	respNilBulk
	respNilArray
	respArray
	respRaw
	respMap
	respVerbatim
)

type RESPValue struct {
	kind  respKind
	str   string
	num   int64
	array []RESPValue
}

// lineSafe mirrors Redis, which replaces CR and LF in status and error replies
// with spaces so client-controlled text cannot break the reply framing.
var lineSafe = strings.NewReplacer("\r", " ", "\n", " ")

func SimpleString(value string) RESPValue {
	return RESPValue{kind: respSimple, str: lineSafe.Replace(value)}
}

func ErrorReply(value string) RESPValue {
	return RESPValue{kind: respError, str: lineSafe.Replace(value)}
}

func IntegerReply(value int64) RESPValue {
	return RESPValue{kind: respInteger, num: value}
}

func BulkString(value string) RESPValue {
	return RESPValue{kind: respBulk, str: value}
}

func NilBulkString() RESPValue {
	return RESPValue{kind: respNilBulk}
}

func NilArray() RESPValue {
	return RESPValue{kind: respNilArray}
}

func Array(values ...RESPValue) RESPValue {
	return RESPValue{kind: respArray, array: values}
}

func BulkArray(values []string) RESPValue {
	items := make([]RESPValue, 0, len(values))
	for _, value := range values {
		items = append(items, BulkString(value))
	}
	return Array(items...)
}

func RawReply(value string) RESPValue {
	return RESPValue{kind: respRaw, str: value}
}

// Map holds alternating key/value items. It encodes as a RESP3 map, or as a
// flat array under RESP2, like Redis' addReplyMapLen.
func Map(pairs ...RESPValue) RESPValue {
	return RESPValue{kind: respMap, array: pairs}
}

// VerbatimText encodes as a RESP3 verbatim string ("txt") or a RESP2 bulk.
func VerbatimText(value string) RESPValue {
	return RESPValue{kind: respVerbatim, str: value}
}

// Bytes encodes the value for a RESP2 connection.
func (v RESPValue) Bytes() []byte {
	return v.Encode(2)
}

// Encode encodes the value for the given protocol version (2 or 3).
func (v RESPValue) Encode(proto int) []byte {
	var buf bytes.Buffer
	v.writeTo(&buf, proto)
	return buf.Bytes()
}

func (v RESPValue) Class() string {
	switch v.kind {
	case respSimple:
		return "simple_string"
	case respError:
		return "error"
	case respInteger:
		return "integer"
	case respBulk:
		return "bulk_string"
	case respNilBulk:
		return "nil_bulk_string"
	case respNilArray:
		return "nil_array"
	case respArray:
		return "array"
	case respRaw:
		return "raw"
	case respMap:
		return "map"
	case respVerbatim:
		return "bulk_string"
	default:
		return "unknown"
	}
}

func (v RESPValue) writeTo(buf *bytes.Buffer, proto int) {
	switch v.kind {
	case respSimple:
		buf.WriteByte('+')
		buf.WriteString(v.str)
		buf.WriteString("\r\n")
	case respError:
		buf.WriteByte('-')
		buf.WriteString(v.str)
		buf.WriteString("\r\n")
	case respInteger:
		buf.WriteByte(':')
		buf.WriteString(strconv.FormatInt(v.num, 10))
		buf.WriteString("\r\n")
	case respBulk:
		writeBulk(buf, '$', v.str)
	case respVerbatim:
		if proto >= 3 {
			writeBulk(buf, '=', "txt:"+v.str)
		} else {
			writeBulk(buf, '$', v.str)
		}
	case respNilBulk:
		if proto >= 3 {
			buf.WriteString("_\r\n")
		} else {
			buf.WriteString("$-1\r\n")
		}
	case respNilArray:
		if proto >= 3 {
			buf.WriteString("_\r\n")
		} else {
			buf.WriteString("*-1\r\n")
		}
	case respArray:
		buf.WriteByte('*')
		buf.WriteString(strconv.Itoa(len(v.array)))
		buf.WriteString("\r\n")
		for _, item := range v.array {
			item.writeTo(buf, proto)
		}
	case respMap:
		if proto >= 3 {
			buf.WriteByte('%')
			buf.WriteString(strconv.Itoa(len(v.array) / 2))
		} else {
			buf.WriteByte('*')
			buf.WriteString(strconv.Itoa(len(v.array)))
		}
		buf.WriteString("\r\n")
		for _, item := range v.array {
			item.writeTo(buf, proto)
		}
	case respRaw:
		buf.WriteString(v.str)
	}
}

func writeBulk(buf *bytes.Buffer, prefix byte, value string) {
	buf.WriteByte(prefix)
	buf.WriteString(strconv.Itoa(len(value)))
	buf.WriteString("\r\n")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

func ReadCommand(reader *bufio.Reader, config ParserConfig) ([]string, error) {
	applyParserDefaults(&config)

	first, err := reader.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] == '*' {
		return readArrayCommand(reader, config)
	}
	return readInlineCommand(reader, config)
}

func applyParserDefaults(config *ParserConfig) {
	if config.MaxBulkBytes <= 0 {
		config.MaxBulkBytes = defaultMaxBulkBytes
	}
	if config.MaxInlineBytes <= 0 {
		config.MaxInlineBytes = defaultMaxInlineBytes
	}
	if config.MaxArrayElems <= 0 {
		config.MaxArrayElems = defaultMaxArrayElems
	}
	if config.MaxCommandBytes <= 0 {
		config.MaxCommandBytes = defaultMaxCommandSize
	}
}

// Protocol error texts match Redis' networking.c so error replies cannot be
// told apart from a real server.
func readArrayCommand(reader *bufio.Reader, config ParserConfig) ([]string, error) {
	line, err := readLine(reader, 64, false)
	if err != nil {
		return nil, protocolLineError(err, "too big mbulk count string")
	}

	count, err := strconv.Atoi(line[1:])
	if err != nil || count > config.MaxArrayElems {
		return nil, fmt.Errorf("invalid multibulk length")
	}
	if count <= 0 {
		return nil, errEmptyCommand
	}

	args := make([]string, 0, count)
	total := 0
	for i := 0; i < count; i++ {
		header, err := readLine(reader, 64, false)
		if err != nil {
			return nil, protocolLineError(err, "too big bulk count string")
		}
		if header == "" || header[0] != '$' {
			got := byte(' ')
			if header != "" {
				got = header[0]
			}
			return nil, fmt.Errorf("expected '$', got '%c'", got)
		}

		size, err := strconv.Atoi(header[1:])
		if err != nil || size < 0 || size > config.MaxBulkBytes {
			return nil, fmt.Errorf("invalid bulk length")
		}
		total += size
		if total > config.MaxCommandBytes {
			return nil, fmt.Errorf("invalid bulk length")
		}

		// Redis skips the two bytes after the payload without checking them.
		data := make([]byte, size+2)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		args = append(args, string(data[:size]))
	}

	return args, nil
}

func readInlineCommand(reader *bufio.Reader, config ParserConfig) ([]string, error) {
	line, err := readLine(reader, config.MaxInlineBytes, true)
	if err != nil {
		return nil, protocolLineError(err, "too big inline request")
	}
	fields, ok := splitArgs(line)
	if !ok {
		return nil, fmt.Errorf("unbalanced quotes in request")
	}
	if len(fields) == 0 {
		return nil, errEmptyCommand
	}
	return fields, nil
}

var errLineTooLong = errors.New("line exceeds limit")

func protocolLineError(err error, tooLong string) error {
	if errors.Is(err, errLineTooLong) {
		return errors.New(tooLong)
	}
	return err
}

func readLine(reader *bufio.Reader, limit int, allowBareLF bool) (string, error) {
	var buf []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > limit {
			return "", errLineTooLong
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return "", err
		}
		break
	}
	if allowBareLF {
		line := buf[:len(buf)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		return string(line), nil
	}
	if len(buf) < 2 || buf[len(buf)-2] != '\r' || buf[len(buf)-1] != '\n' {
		return "", fmt.Errorf("line missing CRLF")
	}
	return string(buf[:len(buf)-2]), nil
}

// splitArgs is a port of Redis' sdssplitargs: double quotes support \xHH,
// \n, \r, \t, \b and \a escapes, single quotes only \', a backslash outside
// quotes is literal, and a closing quote must be followed by a space or the
// end of the line. ok is false for unbalanced quotes.
func splitArgs(line string) (args []string, ok bool) {
	p := 0
	for {
		for p < len(line) && isSplitSpace(line[p]) {
			p++
		}
		if p >= len(line) {
			return args, true
		}

		var current []byte
		inq, insq := false, false
		for done := false; !done; {
			if inq {
				if p >= len(line) {
					return nil, false
				}
				switch {
				case line[p] == '\\' && p+3 < len(line) && line[p+1] == 'x' && isHexDigit(line[p+2]) && isHexDigit(line[p+3]):
					current = append(current, hexValue(line[p+2])*16+hexValue(line[p+3]))
					p += 3
				case line[p] == '\\' && p+1 < len(line):
					p++
					switch line[p] {
					case 'n':
						current = append(current, '\n')
					case 'r':
						current = append(current, '\r')
					case 't':
						current = append(current, '\t')
					case 'b':
						current = append(current, '\b')
					case 'a':
						current = append(current, '\a')
					default:
						current = append(current, line[p])
					}
				case line[p] == '"':
					if p+1 < len(line) && !isSplitSpace(line[p+1]) {
						return nil, false
					}
					done = true
				default:
					current = append(current, line[p])
				}
			} else if insq {
				if p >= len(line) {
					return nil, false
				}
				switch {
				case line[p] == '\\' && p+1 < len(line) && line[p+1] == '\'':
					p++
					current = append(current, '\'')
				case line[p] == '\'':
					if p+1 < len(line) && !isSplitSpace(line[p+1]) {
						return nil, false
					}
					done = true
				default:
					current = append(current, line[p])
				}
			} else {
				if p >= len(line) {
					break
				}
				switch line[p] {
				case ' ', '\n', '\r', '\t', 0:
					done = true
				case '"':
					inq = true
				case '\'':
					insq = true
				default:
					current = append(current, line[p])
				}
			}
			if p < len(line) {
				p++
			}
		}
		args = append(args, string(current))
	}
}

func isSplitSpace(c byte) bool {
	return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\v' || c == '\f'
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexValue(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// approxSize estimates the encoded size of v without encoding it: its strings
// plus a few bytes of framing per value.
func (v RESPValue) approxSize() int64 {
	size := int64(len(v.str)) + 24
	for _, item := range v.array {
		size += item.approxSize()
	}
	return size
}
