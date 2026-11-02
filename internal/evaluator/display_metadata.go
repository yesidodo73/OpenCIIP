package evaluator

import (
	"fmt"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

// fileMetadataDetails exposes metadata already collected by a check. It never
// reads file contents or uses these values to change the check's verdict.
func fileMetadataDetails(evidence []model.Evidence) []model.ResultDetail {
	const maxFiles = 32
	details := make([]model.ResultDetail, 0)
	seen := make(map[string]struct{})
	omitted := 0
	for _, item := range evidence {
		if item.Kind != model.EvidenceFile || item.File == nil {
			continue
		}
		file := item.File
		values := make([]string, 0, 3)
		if file.Owner != "" {
			values = append(values, "소유자="+file.Owner)
		}
		if file.Group != "" {
			values = append(values, "그룹="+file.Group)
		}
		if file.Mode != "" {
			values = append(values, "권한="+file.Mode)
		}
		if len(values) == 0 {
			continue
		}
		source := strings.TrimSpace(file.Path)
		if source == "" {
			source = strings.TrimSpace(item.Source)
		}
		current := strings.Join(values, "  ")
		key := source + "\x00" + current
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if len(details) == maxFiles {
			omitted++
			continue
		}
		details = append(details, model.ResultDetail{Label: "파일 상태", Current: current, Source: source})
	}
	if omitted > 0 {
		details = append(details, model.ResultDetail{
			Label: "표시 범위", Current: fmt.Sprintf("파일 상태 %d개를 추가로 확인했으나 화면에는 표시하지 않았습니다.", omitted),
		})
	}
	return details
}
