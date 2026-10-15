package version

import "testing"

func TestStringDefaults(t *testing.T) {
	if got, want := String(), "dev (none, unknown)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestStringFormat covers the values a release build injects with
// -ldflags "-X github.com/urbnywrt/postern/internal/version.Version=...".
func TestStringFormat(t *testing.T) {
	tests := []struct {
		name    string
		version string
		commit  string
		date    string
		want    string
	}{
		{
			name:    "release",
			version: "v1.2.3",
			commit:  "abc1234",
			date:    "2026-10-04T12:00:00Z",
			want:    "v1.2.3 (abc1234, 2026-10-04T12:00:00Z)",
		},
		{
			name:    "snapshot",
			version: "v1.2.3-4-gabc1234-dirty",
			commit:  "abc1234",
			date:    "2026-10-04T12:00:00Z",
			want:    "v1.2.3-4-gabc1234-dirty (abc1234, 2026-10-04T12:00:00Z)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldVersion, oldCommit, oldDate := Version, Commit, Date
			t.Cleanup(func() { Version, Commit, Date = oldVersion, oldCommit, oldDate })

			Version, Commit, Date = tt.version, tt.commit, tt.date
			if got := String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
