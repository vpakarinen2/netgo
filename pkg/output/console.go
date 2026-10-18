package output

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// Console streams rows in completion order without buffering the scan.
type Console struct {
	writer io.Writer
	header bool
}

func NewConsole(writer io.Writer) *Console { return &Console{writer: writer} }

// Fixed widths keep streamed rows aligned without buffering the whole scan.
// Long display values are shortened; NDJSON retains the full values.
var consoleWidths = [...]int{39, 9, 13, 20, 8, 24, 7, 18, 12}

func (c *Console) writeRow(fields ...string) error {
	var row strings.Builder
	for index, value := range fields {
		value = safeText(value)
		if index < len(consoleWidths) {
			width := consoleWidths[index]
			runes := []rune(value)
			if len(runes) > width {
				value = string(runes[:width-3]) + "..."
			}
			fmt.Fprintf(&row, "%-*s  ", width, value)
		} else {
			row.WriteString(value)
		}
	}
	row.WriteByte('\n')
	_, err := io.WriteString(c.writer, row.String())
	return err
}

func (c *Console) WriteResult(ctx context.Context, result model.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.header {
		if err := c.writeRow("ADDRESS", "PORT", "STATE", "REASON", "ATTEMPTS", "HOSTNAME", "SERVICE", "PRODUCT", "VERSION", "IDENTIFICATION"); err != nil {
			return err
		}
		c.header = true
	}
	var name, product, version, status string
	if result.Service != nil {
		name, product, version = result.Service.Name, result.Service.Product, result.Service.Version
		status = "identified"
	}
	if result.Identification != nil {
		status = result.Identification.Status
	}
	return c.writeRow(result.Target.Address.String(), fmt.Sprintf("%d/%s", result.Target.Port, result.Target.Transport), string(result.State), result.Reason, fmt.Sprint(result.Attempts), result.Target.Hostname, name, product, version, status)
}

func (c *Console) WriteSummary(ctx context.Context, summary model.Summary) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.header && summary.Diagnostics != nil {
		if _, err := io.WriteString(c.writer, "\n"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(c.writer, "Scan %s: %d/%d completed, %d open, %d closed, %d open|filtered, %d filtered, %d unknown, %d attempts in %s\n",
		safeText(summary.Status), summary.Completed, summary.Total, summary.Open, summary.Closed, summary.OpenFiltered, summary.Filtered, summary.Unknown, summary.Attempts, summary.Duration.Round(time.Millisecond))
	if err != nil {
		return err
	}
	if summary.OpenOnly {
		if _, err := fmt.Fprintf(c.writer, "Open-only output: %d result rows shown\n", summary.Reported); err != nil {
			return err
		}
	}
	if summary.Diagnostics != nil {
		return printDiagnostics(c.writer, summary.Diagnostics)
	}
	return nil
}

func (c *Console) Close() error { return nil }

func PrintProgress(writer io.Writer, progress model.Progress) error {
	_, err := fmt.Fprintf(writer, "scan: %d/%d completed, %d open, %d closed, %d open|filtered, %d filtered, %d unknown, %d attempts\n",
		progress.Completed, progress.Total, progress.Open, progress.Closed, progress.OpenFiltered, progress.Filtered, progress.Unknown, progress.Attempts)
	return err
}

func safeText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, value)
}
