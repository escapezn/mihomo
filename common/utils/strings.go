package utils

import (
	"strings"
	"unicode"
)

func Reverse(s string) string {
	a := []rune(s)
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
	return string(a)
}

// IsUnixPath reports whether s looks like a Unix domain socket path.
func IsUnixPath(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Linux abstract namespace socket
	if strings.HasPrefix(s, "@") {
		return true
	}
	// POSIX & Tilde paths
	if strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "~/") ||
		strings.HasPrefix(s, `~\`) {
		return true
	}
	// Windows absolute drive path: C:\... or C:/...
	if len(s) >= 3 && unicode.IsLetter(rune(s[0])) && s[1] == ':' && (s[2] == '/' || s[2] == '\\') {
		return true
	}
	// Windows relative path: .\... or ..\...
	if strings.HasPrefix(s, `.\`) || strings.HasPrefix(s, `..\`) {
		return true
	}
	// Windows root-relative path: \foo\bar.sock
	if strings.HasPrefix(s, `\`) {
		return true
	}
	return false
}
