package output

import (
	"strings"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func webColumns(info *model.WebInfo) (edge, waf string) {
	if info == nil {
		return "-", "-"
	}
	labels := func(detections []model.WebDetection) string {
		values := make([]string, 0, len(detections))
		for _, d := range detections {
			values = append(values, d.Provider+" ["+d.Confidence+"]")
		}
		return strings.Join(values, ", ")
	}
	edge, waf = "-", "unknown"
	if len(info.Edge) > 0 {
		edge = labels(info.Edge)
	}
	if len(info.WAF.Detections) > 0 {
		waf = labels(info.WAF.Detections)
	}
	if len(info.Challenges) > 0 {
		waf += "/challenge"
	}
	if len(info.Warnings) > 0 {
		waf += " ?"
	}
	return edge, waf
}
