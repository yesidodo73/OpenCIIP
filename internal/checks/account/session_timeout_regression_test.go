package account

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const sessionTimeoutRockyProfileDLoop = `for i in /etc/profile.d/*.sh /etc/profile.d/sh.local ; do
    if [ -r "$i" ]; then
        if [ "${-#*i}" != "$-" ]; then
            . "$i"
        else
            . "$i" >/dev/null
        fi
    fi
done
`

func TestSessionTimeoutUsesFinalSourcedStartupState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		files            map[string]string
		wantStatus       model.Status
		observedContains string
	}{
		{
			name: "verified profile loop and bashrc source pass",
			files: map[string]string{
				"/etc/profile":                 sessionTimeoutRockyProfileDLoop,
				"/etc/profile.d/10-timeout.sh": lockedTimeout(600),
				"/etc/bashrc":                  lockedTimeout(600),
				"/root/.bashrc":                "if [ -f /etc/bashrc ]; then\n    . /etc/bashrc\nfi\n",
			},
			wantStatus:       model.StatusPass,
			observedContains: "2개 시작 컨텍스트",
		},
		{
			name: "unreferenced profile script cannot create a pass",
			files: map[string]string{
				"/etc/profile":                 ":\n",
				"/etc/profile.d/10-timeout.sh": lockedTimeout(600),
				"/etc/bashrc":                  lockedTimeout(600),
				"/root/.bashrc":                "if [ -f /etc/bashrc ]; then\n    . /etc/bashrc\nfi\n",
			},
			wantStatus:       model.StatusFail,
			observedContains: "bash-login: TMOUT 없음",
		},
		{
			name: "user login file can override an unlocked global value",
			files: map[string]string{
				"/etc/profile":        "TMOUT=600\nexport TMOUT\n",
				"/root/.bash_profile": lockedTimeout(0),
				"/etc/bashrc":         lockedTimeout(600),
				"/root/.bashrc":       "if [ -f /etc/bashrc ]; then\n    . /etc/bashrc\nfi\n",
			},
			wantStatus:       model.StatusFail,
			observedContains: "TMOUT=0",
		},
		{
			name: "bashrc that does not source the global file cannot pass",
			files: map[string]string{
				"/etc/profile":  lockedTimeout(600),
				"/etc/bashrc":   lockedTimeout(600),
				"/root/.bashrc": ":\n",
			},
			wantStatus:       model.StatusFail,
			observedContains: "readonly 없음",
		},
		{
			name:             "definite absence in all contexts fails",
			files:            map[string]string{},
			wantStatus:       model.StatusFail,
			observedContains: "TMOUT 없음",
		},
		{
			name: "dynamic startup flow remains unknown",
			files: map[string]string{
				"/etc/profile":  "if true; then\nTMOUT=600\nfi\n",
				"/root/.bashrc": "if true; then\nTMOUT=600\nfi\n",
			},
			wantStatus:       model.StatusUnknown,
			observedContains: "조건부",
		},
		{
			name: "altered profile loop remains unknown",
			files: map[string]string{
				"/etc/profile":                 strings.Replace(sessionTimeoutRockyProfileDLoop, `[ -r "$i" ]`, `[ -f "$i" ]`, 1),
				"/etc/profile.d/10-timeout.sh": lockedTimeout(600),
				"/etc/bashrc":                  lockedTimeout(600),
				"/root/.bashrc":                "if [ -f /etc/bashrc ]; then\n    . /etc/bashrc\nfi\n",
			},
			wantStatus:       model.StatusUnknown,
			observedContains: "조건부",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			environment := evaluator.Environment{
				Files:    newAccountFixtureReader(test.files),
				Commands: getentPasswdFixture("root:x:0:0:root:/root:/bin/bash\n"),
			}
			outcome := evaluateSessionTimeout(context.Background(), model.ResolvedRule{}, environment)
			if outcome.Status != test.wantStatus {
				t.Fatalf("status = %q, want %q; outcome = %#v", outcome.Status, test.wantStatus, outcome)
			}
			if !strings.Contains(outcome.Observed, test.observedContains) {
				t.Errorf("observed = %q, want substring %q", outcome.Observed, test.observedContains)
			}
			if outcome.Status != model.StatusPass && len(outcome.Details) == 0 {
				t.Errorf("outcome has no compact display details: %#v", outcome)
			}
		})
	}
}

func TestSessionTimeoutItemsShowsAllHumanDetails(t *testing.T) {
	t.Parallel()

	items := []string{
		"/etc/profile:1 조건부 구문",
		"/etc/profile:2 동적 source",
		"/etc/profile:3 여러 줄 구문",
		"/etc/profile:4 명령 치환",
		"/etc/profile:5 불명확한 분기",
	}
	got := sessionTimeoutItems(items)
	for _, expected := range items {
		if !strings.Contains(got, expected) {
			t.Fatalf("sessionTimeoutItems() lacks %q: %q", expected, got)
		}
	}
	if strings.Contains(got, "; ") {
		t.Fatalf("sessionTimeoutItems() retained semicolon delimiters: %q", got)
	}
}

func TestSessionTimeoutFormattingDoesNotMutateEvidenceSlices(t *testing.T) {
	t.Parallel()

	items := []string{"z 조건", "a 조건", "z 조건", "b 조건"}
	originalItems := append([]string(nil), items...)
	_ = sessionTimeoutItems(items)
	if !reflect.DeepEqual(items, originalItems) {
		t.Fatalf("compactSessionTimeoutItems() mutated input = %#v, want %#v", items, originalItems)
	}

	paths := []string{"/etc/profile", "/etc/bashrc", "/etc/profile", "/root/.bashrc"}
	originalPaths := append([]string(nil), paths...)
	_ = sessionTimeoutSource(paths)
	if !reflect.DeepEqual(paths, originalPaths) {
		t.Fatalf("compactSessionTimeoutSource() mutated input = %#v, want %#v", paths, originalPaths)
	}
}

func TestSessionTimeoutShowsEveryAffectedContext(t *testing.T) {
	t.Parallel()
	var passwd strings.Builder
	for index := 0; index < 6; index++ {
		fmt.Fprintf(&passwd, "user%d:x:%d:%d:user:/home/user%d:/bin/bash\n", index, 1000+index, 1000+index, index)
	}
	outcome := evaluateSessionTimeout(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: newAccountFixtureReader(map[string]string{}), Commands: getentPasswdFixture(passwd.String()),
	})
	if outcome.Status != model.StatusFail || len(outcome.Details) != 12 {
		t.Fatalf("session timeout contexts omitted: %#v", outcome)
	}
	if !strings.HasPrefix(outcome.Details[11].Label, "user5/") {
		t.Fatalf("last account is missing: %#v", outcome.Details)
	}
}

func lockedTimeout(value int) string {
	return "TMOUT=" + strconv.Itoa(value) + "\nexport TMOUT\nreadonly TMOUT\n"
}
