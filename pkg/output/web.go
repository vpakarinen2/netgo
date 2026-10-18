package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func writeWebDetails(writer io.Writer, info *model.WebInfo) error {
	if info == nil || len(info.Edge)+len(info.WAF.Detections)+len(info.Challenges)+len(info.Warnings) == 0 {
		return nil
	}
	labels := func(detections []model.WebDetection) string {
		values := make([]string, 0, len(detections))
		for _, d := range detections {
			values = append(values, d.Provider+" ["+d.Confidence+"]")
		}
		return strings.Join(values, ", ")
	}
	var parts []string
	if len(info.Edge) > 0 {
		parts = append(parts, "edge="+labels(info.Edge))
	}
	if len(info.WAF.Detections) > 0 {
		parts = append(parts, "WAF signal="+labels(info.WAF.Detections))
	} else {
		parts = append(parts, "WAF=unknown")
	}
	if len(info.Challenges) > 0 {
		parts = append(parts, "challenge="+labels(info.Challenges))
	}
	if len(info.Warnings) > 0 {
		parts = append(parts, "warnings="+strings.Join(info.Warnings, ","))
	}
	_, err := fmt.Fprintln(writer, "  Web: "+safeText(strings.Join(parts, "; ")))
	return err
}
