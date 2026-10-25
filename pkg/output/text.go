package output

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// Text streams readable detail blocks, retaining full finding messages without
// collecting or regrouping the scan in memory.
type Text struct {
	writer io.Writer
	wrote  bool
}

func NewText(writer io.Writer) *Text { return &Text{writer: writer} }

func (t *Text) WriteResult(ctx context.Context, result model.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var block strings.Builder
	if t.wrote {
		block.WriteByte('\n')
	}
	endpoint := net.JoinHostPort(result.Target.Address.String(), strconv.Itoa(int(result.Target.Port)))
	fmt.Fprintf(&block, "%s/%s", safeText(endpoint), safeText(string(result.Target.Transport)))
	if result.Target.Hostname != "" {
		fmt.Fprintf(&block, " (%s)", safeText(result.Target.Hostname))
	}
	block.WriteByte('\n')
	line := func(label, value string) {
		if value != "" {
			fmt.Fprintf(&block, "  %s: %s\n", label, safeText(value))
		}
	}
	line("State", string(result.State)+" ("+result.Reason+")")
	line("Probe", fmt.Sprintf("%s, %d attempts, %s", result.Method, result.Attempts, result.Duration.Round(time.Microsecond)))
	if !result.ObservedAt.IsZero() {
		line("Observed", result.ObservedAt.UTC().Format(time.RFC3339))
	}
	if service := result.Service; service != nil {
		line("Service", service.Name)
		product := service.Product
		if service.Version != "" {
			if product != "" {
				product += "/"
			}
			product += service.Version
		}
		line("Product", product)
		for _, evidence := range service.Evidence {
			line("Evidence", evidence.Kind+" = "+evidence.Value)
		}
		if tls := service.TLS; tls != nil {
			line("TLS", tls.Version)
			line("Cipher", tls.CipherSuite)
			line("ALPN", tls.ALPN)
			line("SNI", fmt.Sprintf("sent=%t, name=%s", tls.SNISent, tls.ServerName))
		}
		if web := service.Web; web != nil {
			for _, group := range []struct {
				label string
				items []model.WebDetection
			}{{"Edge", web.Edge}, {"WAF signal", web.WAF.Detections}, {"Challenge", web.Challenges}} {
				for _, detection := range group.items {
					line(group.label, detection.Provider+" ["+detection.Confidence+"]")
					for _, evidence := range detection.Evidence {
						line("  Evidence", evidence.Kind+" = "+evidence.Value)
					}
				}
			}
			line("WAF status", web.WAF.Status)
			for _, warning := range web.Warnings {
				line("Web warning", warning)
			}
		}
	}
	if id := result.Identification; id != nil {
		line("Identification", fmt.Sprintf("%s, %s, %d extra connections", id.Status, id.Duration.Round(time.Microsecond), id.Connections))
		line("Identification error", id.Error)
		for _, evidence := range id.Evidence {
			line("Identification evidence", evidence.Kind+" = "+evidence.Value)
		}
		if id.ReadLimitReached {
			line("Read limit", "reached")
		}
	}
	if udp := result.UDP; udp != nil {
		line("UDP", fmt.Sprintf("%s probe, %d response bytes, %d ignored, %d oversized", udp.Probe, udp.ResponseBytes, udp.IgnoredResponses, udp.OversizedResponses))
	}
	if len(result.Scripts) > 0 {
		block.WriteString("  Scripts:\n")
		for _, run := range result.Scripts {
			fmt.Fprintf(&block, "    %s", safeText(run.ID))
			if run.Version != "" {
				fmt.Fprintf(&block, " v%s", safeText(run.Version))
			}
			fmt.Fprintf(&block, " — %s (%s)\n", safeText(run.Status), run.Duration.Round(time.Microsecond))
			line("    Reason", run.Reason)
			line("    Error", run.Error)
			if run.Status == "completed" && len(run.Findings) == 0 && len(run.Details) == 0 {
				block.WriteString("      No findings.\n")
			}
			for _, detail := range run.Details {
				fmt.Fprintf(&block, "      %s: %s\n", safeText(detail.Label), safeText(detail.Value))
			}
			for _, finding := range run.Findings {
				fmt.Fprintf(&block, "      [%s] %s: %s\n", safeText(finding.Severity), safeText(finding.Kind), safeText(finding.Message))
				line("      Evidence fields", strings.Join(finding.EvidenceFields, ", "))
			}
		}
	}
	_, err := io.WriteString(t.writer, block.String())
	if err == nil {
		t.wrote = true
	}
	return err
}

func (t *Text) WriteSummary(ctx context.Context, summary model.Summary) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var block strings.Builder
	if t.wrote {
		block.WriteByte('\n')
	}
	if err := NewConsole(&block).WriteSummary(ctx, summary); err != nil {
		return err
	}
	if summary.Error != "" {
		fmt.Fprintf(&block, "Error: %s\n", safeText(summary.Error))
	}
	_, err := io.WriteString(t.writer, block.String())
	return err
}

func (t *Text) Close() error { return nil }
