package release_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/release"
)

// The key sets: which keys are trusted for what, from the production keys and
// from the extra keys of a build. The helpers (newKeyPair, keyList, useKeys,
// sign) are in sign_test.go.

func TestSetOf(t *testing.T) {
	tests := []struct {
		component string
		want      release.KeySet
	}{
		{"postern-node", release.ReleaseKeys},
		{"postern-panel", release.ReleaseKeys},
		{"sha256sums", release.ReleaseKeys},
		{"psiphon-core", release.ReleaseKeys}, // the Psiphon client that a release builds
		{"engines-stable", release.StableKeys},
	}
	for _, tc := range tests {
		t.Run(tc.component, func(t *testing.T) {
			got, err := release.SetOf(tc.component)
			if err != nil {
				t.Fatalf("SetOf(%q): %v", tc.component, err)
			}
			if got != tc.want {
				t.Errorf("SetOf(%q) = %v, want %v", tc.component, got, tc.want)
			}
		})
	}
	// The set decides who may sign: a component that is not listed has none. The
	// set that comes with the error is not a real one (the zero value is the
	// release keys): a caller that logs the error and goes on must find that no
	// key is trusted, not that the release keys are.
	for _, component := range []string{"", "postern", "postern-web", "Postern-Node", "postern-node ", "engines-stable\n", "telemt"} {
		set, err := release.SetOf(component)
		if err == nil {
			t.Errorf("SetOf(%q) succeeded, want an error", component)
		}
		if set == release.ReleaseKeys || set == release.StableKeys {
			t.Errorf("SetOf(%q) = %v along with its error, which is a set of keys", component, set)
		}
		if keys, err := release.TrustedKeys(set); err == nil || errors.Is(err, release.ErrNoKeys) || len(keys) != 0 {
			t.Errorf("TrustedKeys of the set that SetOf(%q) gave: %d keys, err = %v, want the refusal of a set that does not exist", component, len(keys), err)
		}
	}
}

func TestTrustedKeys(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		useKeys(t, "", "", "")
		for _, set := range []release.KeySet{release.ReleaseKeys, release.StableKeys} {
			keys, err := release.TrustedKeys(set)
			if !errors.Is(err, release.ErrNoKeys) {
				t.Errorf("TrustedKeys(%v): err = %v, want ErrNoKeys", set, err)
			}
			if len(keys) != 0 {
				t.Errorf("TrustedKeys(%v) returned %d keys along with its error", set, len(keys))
			}
		}
	})
	t.Run("blank lists are none", func(t *testing.T) {
		useKeys(t, " \n\r\n\t", "\n\n", " , ,")
		if _, err := release.TrustedKeys(release.ReleaseKeys); !errors.Is(err, release.ErrNoKeys) {
			t.Errorf("err = %v, want ErrNoKeys", err)
		}
	})
	t.Run("the two sets are apart", func(t *testing.T) {
		a, b := newKeyPair(t), newKeyPair(t)
		useKeys(t, a.pub.String(), b.pub.String(), "")
		rel, err := release.TrustedKeys(release.ReleaseKeys)
		if err != nil || len(rel) != 1 || !rel[0].Equal(a.pub) {
			t.Errorf("release keys = %v, %v, want just a", rel, err)
		}
		stable, err := release.TrustedKeys(release.StableKeys)
		if err != nil || len(stable) != 1 || !stable[0].Equal(b.pub) {
			t.Errorf("stable keys = %v, %v, want just b", stable, err)
		}
	})
	t.Run("forms of a list", func(t *testing.T) {
		a, b, c := newKeyPair(t), newKeyPair(t), newKeyPair(t)
		lists := map[string]string{
			"lines":            keyList("\n", a, b, c),
			"crlf":             keyList("\r\n", a, b, c),
			"commas":           keyList(",", a, b, c),
			"commas and space": keyList(" , ", a, b, c),
			"blank lines":      "\n\n" + keyList("\n\n", a, b, c) + "\n\n",
			"trailing newline": keyList("\n", a, b, c) + "\n",
			"indented":         "  " + keyList("\n\t", a, b, c) + "  ",
			"mixed":            a.pub.String() + "," + b.pub.String() + "\n" + c.pub.String(),
			"pub files": "untrusted comment: minisign public key: AAAA, BBBB\n" + a.pub.String() + "\n" +
				"untrusted comment: minisign public key: CCCC\n" + b.pub.String() + "\n" +
				"untrusted comment: minisign public key: DDDD\n" + c.pub.String() + "\n",
		}
		for name, list := range lists {
			t.Run(name, func(t *testing.T) {
				useKeys(t, list, "", "")
				keys, err := release.TrustedKeys(release.ReleaseKeys)
				if err != nil {
					t.Fatalf("TrustedKeys: %v", err)
				}
				if len(keys) != 3 || !keys[0].Equal(a.pub) || !keys[1].Equal(b.pub) || !keys[2].Equal(c.pub) {
					t.Errorf("got %d keys, want a, b, c in that order", len(keys))
				}
			})
		}
	})
	t.Run("malformed", func(t *testing.T) {
		good := newKeyPair(t)
		short := base64.StdEncoding.EncodeToString([]byte("too short, MARKERMARKER"))
		wrongAlgorithm := make([]byte, 42)
		binary.LittleEndian.PutUint16(wrongAlgorithm, 0x1234)
		tests := []struct {
			name     string
			list     string
			position string
			bad      string // the entry that must not be quoted
		}{
			{"not base64", "!!MARKERMARKER!!", "key 1", "!!MARKERMARKER!!"},
			{"too short", short, "key 1", short},
			{"wrong algorithm", base64.StdEncoding.EncodeToString(wrongAlgorithm), "key 1", base64.StdEncoding.EncodeToString(wrongAlgorithm)},
			{"the second of two", good.pub.String() + "\n!!MARKERMARKER!!", "key 2", "!!MARKERMARKER!!"},
			{"the third, after blank lines and a comment", good.pub.String() + "\n\nuntrusted comment: x\n" + good.pub.String() + "\n" + short, "key 3", short},
			{"a private key is no public key", "untrusted comment: minisign encrypted secret key\n" + short, "key 1", short},
		}
		for _, tc := range tests {
			for _, set := range []release.KeySet{release.ReleaseKeys, release.StableKeys} {
				t.Run(tc.name+"/"+set.String(), func(t *testing.T) {
					if set == release.ReleaseKeys {
						useKeys(t, tc.list, "", "")
					} else {
						useKeys(t, "", tc.list, "")
					}
					keys, err := release.TrustedKeys(set)
					if err == nil {
						t.Fatal("TrustedKeys succeeded for a malformed key")
					}
					if errors.Is(err, release.ErrNoKeys) {
						t.Errorf("err = %v: a malformed key is not an absent one", err)
					}
					if len(keys) != 0 {
						t.Errorf("returned %d keys along with its error", len(keys))
					}
					msg := err.Error()
					if !strings.Contains(msg, tc.position) {
						t.Errorf("err = %q, want it to name %q", msg, tc.position)
					}
					if !strings.Contains(msg, set.String()) {
						t.Errorf("err = %q, want it to name the set (%s)", msg, set)
					}
					// Never the key: not the entry, not a piece of it.
					if strings.Contains(msg, "MARKER") || strings.Contains(msg, tc.bad) || strings.Contains(msg, tc.bad[:min(12, len(tc.bad))]) {
						t.Errorf("err = %q quotes the key", msg)
					}
				})
			}
		}
	})
	t.Run("a malformed key is not ignored in favour of the extra keys", func(t *testing.T) {
		// A botched production list must not fall back to test keys.
		extra := newKeyPair(t)
		useKeys(t, "!!botched!!", "", keyList(",", extra))
		if _, err := release.TrustedKeys(release.ReleaseKeys); err == nil || errors.Is(err, release.ErrNoKeys) {
			t.Errorf("err = %v, want the error of the malformed production key", err)
		}
	})
	t.Run("a malformed extra key", func(t *testing.T) {
		good := newKeyPair(t)
		useKeys(t, "", "", keyList(",", good)+",!!MARKERMARKER!!")
		_, err := release.TrustedKeys(release.ReleaseKeys)
		if err == nil {
			t.Fatal("TrustedKeys succeeded for a malformed extra key")
		}
		if !strings.Contains(err.Error(), "key 2") || strings.Contains(err.Error(), "MARKER") {
			t.Errorf("err = %q, want it to name key 2 and not to quote it", err)
		}
	})
	t.Run("an unknown set", func(t *testing.T) {
		useKeys(t, "", "", "")
		for _, set := range []release.KeySet{-1, 2, 99} {
			if _, err := release.TrustedKeys(set); err == nil || errors.Is(err, release.ErrNoKeys) {
				t.Errorf("TrustedKeys(%d): err = %v, want an error that says the set is unknown", int(set), err)
			}
		}
	})
}

func TestProductionKeys(t *testing.T) {
	a, b, extra := newKeyPair(t), newKeyPair(t), newKeyPair(t)

	t.Run("none", func(t *testing.T) {
		useKeys(t, "", "", keyList(",", extra))
		for _, set := range []release.KeySet{release.ReleaseKeys, release.StableKeys} {
			if keys := release.ProductionKeys(set); len(keys) != 0 {
				t.Errorf("ProductionKeys(%v) = %d keys, want none (the extra keys are not production keys)", set, len(keys))
			}
		}
	})
	t.Run("the keys of the set, in order", func(t *testing.T) {
		useKeys(t, keyList("\n", a, b), keyList("\n", b), keyList(",", extra))
		rel := release.ProductionKeys(release.ReleaseKeys)
		if len(rel) != 2 || !rel[0].Equal(a.pub) || !rel[1].Equal(b.pub) {
			t.Errorf("ProductionKeys(ReleaseKeys) = %d keys, want a, b", len(rel))
		}
		stable := release.ProductionKeys(release.StableKeys)
		if len(stable) != 1 || !stable[0].Equal(b.pub) {
			t.Errorf("ProductionKeys(StableKeys) = %d keys, want b", len(stable))
		}
	})
	t.Run("a malformed key is left out", func(t *testing.T) {
		// TrustedKeys is the one that complains; this is for listing what is there.
		useKeys(t, a.pub.String()+"\n!!bad!!\n"+b.pub.String(), "", "")
		rel := release.ProductionKeys(release.ReleaseKeys)
		if len(rel) != 2 || !rel[0].Equal(a.pub) || !rel[1].Equal(b.pub) {
			t.Errorf("ProductionKeys(ReleaseKeys) = %d keys, want a, b", len(rel))
		}
	})
	t.Run("an unknown set", func(t *testing.T) {
		useKeys(t, keyList("\n", a), keyList("\n", a), "")
		if keys := release.ProductionKeys(release.KeySet(7)); len(keys) != 0 {
			t.Errorf("ProductionKeys(7) = %d keys, want none", len(keys))
		}
	})
}

func TestExtraKeys(t *testing.T) {
	prod, extra, extra2 := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	data := randomBytes(t, 4096)
	byExtra := sign(t, data, extra, nodeAMD64)
	byProd := sign(t, data, prod, nodeAMD64)

	t.Run("the production keys are empty: the extra keys are used", func(t *testing.T) {
		useKeys(t, "", "", keyList(",", extra))
		for _, set := range []release.KeySet{release.ReleaseKeys, release.StableKeys} {
			keys, err := release.TrustedKeys(set)
			if err != nil || len(keys) != 1 || !keys[0].Equal(extra.pub) {
				t.Errorf("TrustedKeys(%v) = %d keys, %v, want just the extra key", set, len(keys), err)
			}
		}
		if err := release.Verify(bytes.NewReader(data), byExtra, nodeAMD64); err != nil {
			t.Errorf("a signature by an extra key: %v", err)
		}
		if got, want := release.KeyWarnings(), []string{"test-release-keys"}; !slices.Equal(got, want) {
			t.Errorf("KeyWarnings() = %q, want %q", got, want)
		}
	})
	t.Run("the production keys exist: the extra keys are ignored", func(t *testing.T) {
		useKeys(t, keyList("\n", prod), keyList("\n", prod), keyList(",", extra))
		for _, set := range []release.KeySet{release.ReleaseKeys, release.StableKeys} {
			keys, err := release.TrustedKeys(set)
			if err != nil || len(keys) != 1 || !keys[0].Equal(prod.pub) {
				t.Errorf("TrustedKeys(%v) = %d keys, %v, want just the production key", set, len(keys), err)
			}
		}
		if err := release.Verify(bytes.NewReader(data), byExtra, nodeAMD64); !errors.Is(err, release.ErrUntrustedKey) {
			t.Errorf("a signature by an ignored extra key: err = %v, want ErrUntrustedKey", err)
		}
		if err := release.Verify(bytes.NewReader(data), byProd, nodeAMD64); err != nil {
			t.Errorf("a signature by the production key: %v", err)
		}
		if got, want := release.KeyWarnings(), []string{"test-release-keys-ignored"}; !slices.Equal(got, want) {
			t.Errorf("KeyWarnings() = %q, want %q", got, want)
		}
	})
	t.Run("a set at a time", func(t *testing.T) {
		// Production release keys, no production stable keys: the extra keys
		// serve the stable set only, and both warnings are given.
		useKeys(t, keyList("\n", prod), "", keyList(",", extra))
		rel, err := release.TrustedKeys(release.ReleaseKeys)
		if err != nil || len(rel) != 1 || !rel[0].Equal(prod.pub) {
			t.Errorf("release keys = %d, %v, want just the production key", len(rel), err)
		}
		stable, err := release.TrustedKeys(release.StableKeys)
		if err != nil || len(stable) != 1 || !stable[0].Equal(extra.pub) {
			t.Errorf("stable keys = %d, %v, want just the extra key", len(stable), err)
		}
		want := []string{"test-release-keys", "test-release-keys-ignored"}
		if got := release.KeyWarnings(); !slices.Equal(got, want) {
			t.Errorf("KeyWarnings() = %q, want %q", got, want)
		}

		// And the other way round.
		useKeys(t, "", keyList("\n", prod), keyList(",", extra))
		if got := release.KeyWarnings(); !slices.Equal(got, want) {
			t.Errorf("KeyWarnings() = %q, want %q", got, want)
		}
	})
	t.Run("several extra keys", func(t *testing.T) {
		useKeys(t, "", "", keyList(",", extra, extra2))
		keys, err := release.TrustedKeys(release.StableKeys)
		if err != nil || len(keys) != 2 || !keys[0].Equal(extra.pub) || !keys[1].Equal(extra2.pub) {
			t.Fatalf("TrustedKeys = %d keys, %v, want both extra keys", len(keys), err)
		}
		sig2 := sign(t, data, extra2, nodeAMD64)
		if err := release.Verify(bytes.NewReader(data), sig2, nodeAMD64); err != nil {
			t.Errorf("a signature by the second extra key: %v", err)
		}
	})
	t.Run("no extra keys, no warnings", func(t *testing.T) {
		for _, production := range []string{"", keyList("\n", prod)} {
			useKeys(t, production, production, "")
			if got := release.KeyWarnings(); len(got) != 0 {
				t.Errorf("KeyWarnings() = %q, want none (production keys %q)", got, production)
			}
		}
	})
	t.Run("blank extra keys, no warnings", func(t *testing.T) {
		useKeys(t, "", "", " , \n")
		if got := release.KeyWarnings(); len(got) != 0 {
			t.Errorf("KeyWarnings() = %q, want none", got)
		}
	})
}

func TestKeySetString(t *testing.T) {
	if got := release.ReleaseKeys.String(); got != "release" {
		t.Errorf("ReleaseKeys.String() = %q, want release", got)
	}
	if got := release.StableKeys.String(); got != "stable" {
		t.Errorf("StableKeys.String() = %q, want stable", got)
	}
	if release.ReleaseKeys == release.StableKeys {
		t.Error("the two key sets are one")
	}
	if got := release.KeySet(9).String(); got == "" {
		t.Error("an unknown key set has no name")
	}
}
