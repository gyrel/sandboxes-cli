package command

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	diagnoseTailLines = 2000
	diagnoseTailBytes = 4 << 20
)

// diagnoseLogTail retains the newest complete JSONL records within both limits.
// A record without a valid timestamp is excluded when a cutoff is requested.
func diagnoseLogTail(r io.Reader, since time.Time) ([]byte, error) {
	reader := bufio.NewReader(r)
	lines := make([][]byte, 0, diagnoseTailLines)
	size := 0
	for {
		line, err := diagnoseReadRecord(reader)
		if len(line) > 0 && len(line) <= diagnoseTailBytes && diagnoseLogAfter(line, since) {
			copyLine := bytes.Clone(line)
			copyLine = diagnoseTerminateLine(copyLine)
			if len(copyLine) <= diagnoseTailBytes {
				for len(lines) > 0 && (len(lines) >= diagnoseTailLines || size+len(copyLine) > diagnoseTailBytes) {
					size -= len(lines[0])
					lines[0] = nil
					lines = lines[1:]
				}
				lines = append(lines, copyLine)
				size += len(copyLine)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
	}
	return bytes.Join(lines, nil), nil
}

func diagnoseTerminateLine(line []byte) []byte {
	if line[len(line)-1] != '\n' {
		return append(line, '\n')
	}
	return line
}

// diagnoseReadRecord consumes one record without retaining more than the limit.
func diagnoseReadRecord(reader *bufio.Reader) ([]byte, error) {
	var record []byte
	oversized := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(record)+len(fragment) > diagnoseTailBytes {
			oversized = true
		}
		if !oversized {
			record = append(record, fragment...)
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if oversized {
				return nil, err
			}
			return record, err
		}
	}
}

func diagnoseLogAfter(line []byte, since time.Time) bool {
	if since.IsZero() {
		return true
	}
	var entry struct {
		Timestamp time.Time `json:"ts"`
	}
	return json.Unmarshal(line, &entry) == nil && !entry.Timestamp.IsZero() && !entry.Timestamp.Before(since)
}
