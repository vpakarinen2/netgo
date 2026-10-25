package output

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// Progress and its underlying writer share the dispatcher's serial coordinator.
// Carriage returns/spaces work without ANSI support. Only interactive console/text
// mode rewrites a line; redirected output remains an ordinary line stream.
type Progress struct {
	Writer
	stderr      io.Writer
	interactive bool
	width       func() int
	last        model.Progress
	hasProgress bool
	visible     int
}

func NewProgress(writer Writer, stderr io.Writer, interactive bool, width func() int) *Progress {
	return &Progress{Writer: writer, stderr: stderr, interactive: interactive, width: width}
}

func (p *Progress) columns() int {
	columns := 80
	if p.width != nil {
		columns = p.width()
	}
	return max(0, columns-1)
}

func (p *Progress) clear() error {
	if p.visible == 0 {
		return nil
	}
	_, err := io.WriteString(p.stderr, "\r"+strings.Repeat(" ", min(p.visible, p.columns()))+"\r")
	p.visible = 0
	return err
}

func (p *Progress) draw() error {
	if !p.hasProgress {
		return nil
	}
	s := p.last
	line := fmt.Sprintf("scan: %d/%d | open %d | closed %d | uncertain %d | attempts %d", s.Completed, s.Total, s.Open, s.Closed, s.Unknown+s.OpenFiltered+s.Filtered, s.Attempts)
	columns := p.columns()
	if len(line) > columns {
		line = line[:columns]
	}
	_, err := io.WriteString(p.stderr, "\r"+line)
	p.visible = len(line)
	return err
}

func (p *Progress) Report(progress model.Progress) error {
	if !p.interactive {
		return PrintProgress(p.stderr, progress)
	}
	if err := p.clear(); err != nil {
		return err
	}
	p.last, p.hasProgress = progress, true
	return p.draw()
}

func (p *Progress) WriteResult(ctx context.Context, result model.Result) error {
	if err := p.clear(); err != nil {
		return err
	}
	if err := p.Writer.WriteResult(ctx, result); err != nil {
		return err
	}
	return p.draw()
}

func (p *Progress) WriteSummary(ctx context.Context, summary model.Summary) error {
	if err := p.clear(); err != nil {
		return err
	}
	p.hasProgress = false
	return p.Writer.WriteSummary(ctx, summary)
}

func (p *Progress) Close() error { return errors.Join(p.clear(), p.Writer.Close()) }
