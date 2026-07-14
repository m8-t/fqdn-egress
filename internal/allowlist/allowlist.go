package allowlist

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// List is an immutable set of allowed FQDNs. Plain entries match exactly;
// entries of the form *.example.com match any subdomain of example.com but
// not example.com itself.
type List struct {
	exact    map[string]struct{}
	wildcard map[string]struct{}
}

func Load(path string) (*List, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	l, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

func Parse(r io.Reader) (*List, error) {
	l := &List{
		exact:    make(map[string]struct{}),
		wildcard: make(map[string]struct{}),
	}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, wild := strings.CutPrefix(line, "*.")
		name = normalize(name)
		if err := validate(name); err != nil {
			return nil, fmt.Errorf("line %d: %q: %w", n, line, err)
		}
		if wild {
			l.wildcard[name] = struct{}{}
		} else {
			l.exact[name] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return l, nil
}

// Match reports whether name is covered by the list. Matching is
// case-insensitive and ignores a trailing dot.
func (l *List) Match(name string) bool {
	name = normalize(name)
	if _, ok := l.exact[name]; ok {
		return true
	}
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
		if _, ok := l.wildcard[name]; ok {
			return true
		}
	}
}

func (l *List) Len() int {
	return len(l.exact) + len(l.wildcard)
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func validate(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return fmt.Errorf("empty label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("label starts or ends with a hyphen")
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return fmt.Errorf("invalid character %q", c)
			}
		}
	}
	return nil
}
