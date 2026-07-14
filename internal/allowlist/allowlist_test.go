package allowlist

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, input string) *List {
	t.Helper()
	l, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return l
}

func TestParse(t *testing.T) {
	l := mustParse(t, `
# comment
github.com
gitlab.com   # trailing comment

*.archlinux.org
Example.COM.
`)
	if l.Len() != 4 {
		t.Errorf("Len = %d, want 4", l.Len())
	}
}

func TestParseErrors(t *testing.T) {
	for _, input := range []string{
		"foo..com",
		"-foo.com",
		"foo-.com",
		"foo.com/path",
		"http://foo.com",
		"*.",
		"foo bar.com",
	} {
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Errorf("Parse(%q): expected error", input)
		}
	}
}

func TestParseErrorHasLineNumber(t *testing.T) {
	_, err := Parse(strings.NewReader("ok.com\nbad..name\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("expected line 2 in error, got %v", err)
	}
}

func TestMatch(t *testing.T) {
	l := mustParse(t, `
github.com
*.archlinux.org
`)
	tests := []struct {
		name string
		want bool
	}{
		{"github.com", true},
		{"GitHub.COM", true},
		{"github.com.", true},
		{"api.github.com", false}, // exact entries do not cover subdomains
		{"aur.archlinux.org", true},
		{"deep.sub.archlinux.org", true},
		{"archlinux.org", false}, // wildcard does not cover the parent
		{"evilarchlinux.org", false},
		{"github.com.evil.net", false},
		{"example.com", false},
		{"com", false},
	}
	for _, tt := range tests {
		if got := l.Match(tt.name); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMatchEmptyList(t *testing.T) {
	l := mustParse(t, "")
	if l.Match("github.com") {
		t.Error("empty list matched")
	}
}
