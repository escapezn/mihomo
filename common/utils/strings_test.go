package utils

import "testing"

func TestIsUnixPath(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "absolute path",
			s:    "/var/run/mihomo.sock",
			want: true,
		},
		{
			name: "relative dot-slash",
			s:    "./mihomo.sock",
			want: true,
		},
		{
			name: "relative dot-dot-slash",
			s:    "../mihomo.sock",
			want: true,
		},
		{
			name: "home directory",
			s:    "~/mihomo.sock",
			want: true,
		},
		{
			name: "abstract socket full",
			s:    "@/tmp/mihomo.sock",
			want: true,
		},
		{
			name: "abstract socket name",
			s:    "@mihomo.sock",
			want: true,
		},
		{
			name: "windows absolute backslash",
			s:    `C:\Users\test\mihomo.sock`,
			want: true,
		},
		{
			name: "windows absolute slash",
			s:    "C:/Users/test/mihomo.sock",
			want: true,
		},
		{
			name: "windows relative backslash",
			s:    `.\mihomo.sock`,
			want: true,
		},
		{
			name: "windows relative parent backslash",
			s:    `..\mihomo.sock`,
			want: true,
		},
		{
			name: "windows root relative",
			s:    `\mihomo.sock`,
			want: true,
		},
		{
			name: "tilde backslash",
			s:    `~\mihomo.sock`,
			want: true,
		},
		{
			name: "host port",
			s:    "127.0.0.1:7890",
			want: false,
		},
		{
			name: "hostname port",
			s:    "example.com:8388",
			want: false,
		},
		{
			name: "port number string",
			s:    "7890",
			want: false,
		},
		{
			name: "empty string",
			s:    "",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUnixPath(tt.s); got != tt.want {
				t.Errorf("IsUnixPath(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}
