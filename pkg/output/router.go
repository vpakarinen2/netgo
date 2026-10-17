package output

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// New routes the selected format to stdout and optionally a new file. Existing
// files are never overwritten. Call Close even when scanning fails.
func New(format string, stdout io.Writer, path string) (Writer, error) {
	if stdout == nil {
		return nil, fmt.Errorf("stdout writer is required")
	}
	if format != "console" && format != "ndjson" {
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
	var file *os.File
	writer := stdout
	if path != "" {
		var err error
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, fmt.Errorf("create output %q: %w", path, err)
		}
		writer = io.MultiWriter(stdout, file)
	}
	var sink Writer
	if format == "console" {
		sink = NewConsole(writer)
	} else {
		sink = NewJSON(writer)
	}
	return &router{Writer: sink, file: file}, nil
}

type router struct {
	Writer
	file   *os.File
	closed bool
}

func (r *router) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	err := r.Writer.Close()
	if r.file != nil {
		err = errors.Join(err, r.file.Close())
	}
	return err
}
