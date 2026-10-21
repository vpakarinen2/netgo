package output

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"
	"golang.org/x/text/width"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// Console streams rows in completion order without buffering the scan.
type Console struct {
	writer       io.Writer
	header       bool
	width        func() int
	layout       []consoleColumn
	rowLimit     int
	addressWidth int
	showService  bool
}

func NewConsole(writer io.Writer) *Console {
	return NewConsoleWithWidth(writer, terminalColumns(writer))
}

// A nil width retains every column for redirected output. Width is checked for
// each result so terminal resizing also works when progress is disabled.
func NewConsoleWithWidth(writer io.Writer, columns func() int) *Console {
	return &Console{writer: writer, width: columns}
}

func terminalColumns(writer io.Writer) func() int {
	file, ok := writer.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil
	}
	return func() int {
		if columns, _, err := term.GetSize(int(file.Fd())); err == nil && columns > 0 {
			return columns
		}
		return 80
	}
}

// Fixed widths keep streamed rows aligned without buffering the whole scan.
// Long display values are shortened; NDJSON retains the full values.
var consoleWidths = [...]int{39, 9, 13, 20, 20, 7, 18, 20, 18, 14}
var consoleHeaders = [...]string{"ADDRESS", "PORT", "STATE", "REASON", "HOSTNAME", "SERVICE", "PRODUCT/VERSION", "EDGE", "WAF", "IDENTIFICATION"}

type consoleColumn struct{ field, width int }

func (c *Console) columns(address string) []consoleColumn {
	columns := 0
	if c.width != nil {
		columns = max(1, c.width()-1) // Avoid terminal autowrap at the right edge.
	}
	c.rowLimit = columns
	if columns == 0 || columns >= 196 {
		layout := make([]consoleColumn, len(consoleWidths))
		for index, size := range consoleWidths {
			layout[index] = consoleColumn{index, size}
		}
		return layout
	}
	// Keep a stable address width as IPv4/IPv6 results interleave. Grow when
	// needed, but do not alternate headers for every change of address family.
	c.addressWidth = max(c.addressWidth, 15, textWidth(address))
	sizes := [10]int{c.addressWidth, 9, 13}
	used := sizes[0] + sizes[1] + sizes[2] + 4
	// Below normal terminal widths, keep endpoint/state columns as useful as
	// possible. Individual values are visibly shortened rather than wrapped.
	for _, field := range []int{0, 2, 1} {
		minimum := 3
		if field == 2 {
			minimum = 5
		}
		shrink := min(max(0, used-columns), sizes[field]-minimum)
		sizes[field] -= shrink
		used -= shrink
	}
	optional := []consoleColumn{{3, 20}, {4, 20}}
	if c.showService {
		optional = append([]consoleColumn{{5, 7}, {7, 15}, {8, 10}, {6, 15}, {9, 14}}, optional...)
	}
	for _, column := range optional {
		if used+column.width+2 <= columns {
			sizes[column.field] = column.width
			used += column.width + 2
		}
	}
	for _, field := range []int{7, 8, 6, 0} {
		if sizes[field] > 0 {
			extra := min(max(0, columns-used), consoleWidths[field]-sizes[field])
			sizes[field] += extra
			used += extra
		}
	}
	var layout []consoleColumn
	for field, size := range sizes {
		if size > 0 {
			layout = append(layout, consoleColumn{field, size})
		}
	}
	return layout
}

func (c *Console) writeRow(fields ...string) error {
	var row strings.Builder
	for index, column := range c.layout {
		if index > 0 {
			row.WriteString("  ")
		}
		value := fitText(safeText(fields[column.field]), column.width)
		row.WriteString(value)
		if index < len(c.layout)-1 {
			row.WriteString(strings.Repeat(" ", column.width-textWidth(value)))
		}
	}
	line := strings.TrimRight(row.String(), " ")
	if c.rowLimit > 0 {
		line = fitText(line, c.rowLimit)
	}
	_, err := io.WriteString(c.writer, line+"\n")
	return err
}

func (c *Console) WriteResult(ctx context.Context, result model.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.showService = c.showService || result.Service != nil || result.Identification != nil
	layout := c.columns(result.Target.Address.String())
	changed := len(layout) != len(c.layout)
	if !changed {
		for index := range layout {
			if layout[index] != c.layout[index] {
				changed = true
				break
			}
		}
	}
	if !c.header || changed {
		c.layout = layout
		if err := c.writeRow(consoleHeaders[:]...); err != nil {
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
	if version != "" {
		if product != "" {
			product += "/"
		}
		product += version
	}
	edge, waf := "-", "-"
	if result.Service != nil {
		edge, waf = webColumns(result.Service.Web)
	}
	return c.writeRow(result.Target.Address.String(), fmt.Sprintf("%d/%s", result.Target.Port, result.Target.Transport), string(result.State), result.Reason, result.Target.Hostname, name, product, edge, waf, status)
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
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, value)
}

func runeWidth(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
		return 0
	}
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	}
	return 1
}

func textWidth(value string) int {
	columns := 0
	for _, r := range value {
		columns += runeWidth(r)
	}
	return columns
}

func fitText(value string, columns int) string {
	if textWidth(value) <= columns {
		return value
	}
	suffix := strings.Repeat(".", min(3, columns))
	var prefix strings.Builder
	used := 0
	for _, r := range value {
		if used+runeWidth(r) > columns-len(suffix) {
			break
		}
		prefix.WriteRune(r)
		used += runeWidth(r)
	}
	return prefix.String() + suffix
}
