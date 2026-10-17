package service

import (
	"bytes"
	"io"
	"net"
)

// readAhead stops at a complete SSH identification line, HTTP header block,
// byte limit, EOF, or the deadline installed by the caller. It reads no bodies
// deliberately, although the final socket read may include a bounded prefix.
func readAhead(conn net.Conn, limit int) ([]byte, error) {
	data := make([]byte, 0, min(limit, 4096))
	buffer := make([]byte, min(limit, 1024))
	for len(data) < limit {
		n, err := conn.Read(buffer[:min(len(buffer), limit-len(data))])
		data = append(data, buffer[:n]...)
		if completeBanner(data) {
			return data, nil
		}
		if err != nil {
			return data, err
		}
		if n == 0 {
			return data, io.ErrNoProgress
		}
	}
	return data, nil
}

func completeBanner(data []byte) bool {
	if bytes.HasPrefix(data, []byte("HTTP/")) {
		return bytes.Contains(data, []byte("\r\n\r\n")) || bytes.Contains(data, []byte("\n\n"))
	}
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("SSH-")) && bytes.HasSuffix(line, []byte("\n")) {
			return true
		}
	}
	return false
}
