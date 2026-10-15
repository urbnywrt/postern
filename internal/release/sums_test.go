package release_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/release"
)

// The checksum files of the upstream releases that are pinned, as they are
// published (the digests are the public ones; the formats were looked at on
// 2026-10-05).
const (
	// https://github.com/telemt/telemt/releases/download/3.5.13/telemt-x86_64-linux-musl.tar.gz.sha256
	telemtSum = "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43  telemt-x86_64-linux-musl.tar.gz\n"

	// The lines of https://github.com/9seconds/mtg/releases/download/v2.2.8/mtg-2.2.8-checksums.txt
	// that matter: a platform has two builds (amd64 and amd64-v3, arm64 and arm64-v9.0),
	// the names of which are one inside the other.
	mtgSums = `178f7903c2e2aa82f7cc045438f10ca30e7469c579e6de85caf52fc450890a65  mtg-2.2.8-darwin-amd64.tar.gz
98af09fb555749aa446d1aec35efc2065ad1ed630abacd5299c703f75cc0cbe6  mtg-2.2.8-darwin-arm64.tar.gz
99c2f177730271b88d8f2404b2cf27d5ee997685f6d9118d4c8cac9c5aaedf50  mtg-2.2.8-linux-386.tar.gz
00d739adf90edcd53e7671b08317b43fa45357fc912046510513155c1351b152  mtg-2.2.8-linux-amd64-v3.tar.gz
7ef19d079d85f4e00d4f8334ec1f3f3c8718e3d0ed1f3109ea9a8673138a2102  mtg-2.2.8-linux-amd64.tar.gz
dd3c994a22a22d7f2345b3580448db5fa67a1f23ed09dd14e3880d0510d43bc9  mtg-2.2.8-linux-arm64-v9.0.tar.gz
562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644  mtg-2.2.8-linux-arm64.tar.gz
9b2061ba01661d60411798e0a63e6cbc9430c6c1398e1b20c01e4a66ca9a1d82  mtg-2.2.8-linux-armv6.tar.gz
368f21a417687e23803f672d6c5ebcfab8c03fbdc0e4dcb7a3e3e11d36a066c8  mtg-2.2.8-windows-amd64.zip
`

	// https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip.dgst
	xrayDgst = `MD5= ee4e2ff74948a9b464624b1cabc44409
SHA1= b55b06e74e89083b9cedfdecf0d68b579cd2af72
SHA2-256= 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
SHA2-512= e8bc40a0687cac184bbe4b5c1f047e69064ccedc489fb25e208889ae287bbf8736dff16b108d68fc00dc33edc8bb53502e47a9698a277f4f51b67b83d899e518
`

	// https://github.com/bepass-org/warp-plus/releases/download/v1.2.6/warp-plus_linux-amd64.zip.dgst
	warpDgst = `MD5= e8611f25b6f9696f4535da0addbfeca6
SHA2-256= 380d2c8655b33db818adf407c706d52d14c2ab1764e702e91f356a7d7d9c3c98
SHA2-512= c167107a2593a5bf6dae90e5bbe7519db3706b1c1b768765e4dd0c3d0d31d1865b18cf045e5f8f9b85f28d54ced33dc12546425b573bf808e84a75a1fcc29dc1
`
)

const (
	hexA = "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43"
	hexB = "f7b5181f1160e9ec73eb28705040bf159782055ec71f54a20214e2c9a6d997cd"
)

// TestSumFor is the cases of SumFor, as groups of subtests so that one run of
// -run '^TestSumFor$' takes all of them.
func TestSumFor(t *testing.T) {
	t.Run("sha256sum", sumForSHA256)
	t.Run("no sum", sumForNoSum)
	t.Run("a file that cannot be trusted", sumForRefused)
	t.Run("dgst", sumForDgst)
	t.Run("unknown format", sumForUnknownFormat)
	t.Run("errors do not quote the file", sumForErrorsDoNotQuoteTheFile)
}

func sumForSHA256(t *testing.T) {
	const (
		telemtAMD64 = "telemt-x86_64-linux-musl.tar.gz"
		telemtARM64 = "telemt-aarch64-linux-musl.tar.gz"
	)
	tests := []struct {
		name string
		file string // the name that is looked for
		data string
		want string
	}{
		// The files of the upstream releases.
		{"telemt", telemtAMD64, telemtSum, hexA},
		{"mtg amd64", "mtg-2.2.8-linux-amd64.tar.gz", mtgSums, "7ef19d079d85f4e00d4f8334ec1f3f3c8718e3d0ed1f3109ea9a8673138a2102"},
		{"mtg amd64, the other build", "mtg-2.2.8-linux-amd64-v3.tar.gz", mtgSums, "00d739adf90edcd53e7671b08317b43fa45357fc912046510513155c1351b152"},
		{"mtg arm64", "mtg-2.2.8-linux-arm64.tar.gz", mtgSums, "562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644"},
		{"mtg arm64, the other build", "mtg-2.2.8-linux-arm64-v9.0.tar.gz", mtgSums, "dd3c994a22a22d7f2345b3580448db5fa67a1f23ed09dd14e3880d0510d43bc9"},
		{"mtg first line", "mtg-2.2.8-darwin-amd64.tar.gz", mtgSums, "178f7903c2e2aa82f7cc045438f10ca30e7469c579e6de85caf52fc450890a65"},
		{"mtg last line, a zip", "mtg-2.2.8-windows-amd64.zip", mtgSums, "368f21a417687e23803f672d6c5ebcfab8c03fbdc0e4dcb7a3e3e11d36a066c8"},

		// The two forms of sha256sum: text and binary.
		{"text mode", "a.tar.gz", hexA + "  a.tar.gz\n", hexA},
		{"binary mode", "a.tar.gz", hexA + " *a.tar.gz\n", hexA},
		{"binary mode, two files", "b.tar.gz", hexA + " *a.tar.gz\n" + hexB + " *b.tar.gz\n", hexB},
		{"no newline at the end", "a.tar.gz", hexA + "  a.tar.gz", hexA},
		{"windows line ends", "b.tar.gz", hexA + "  a.tar.gz\r\n" + hexB + "  b.tar.gz\r\n", hexB},
		{"windows line ends, binary", "b.tar.gz", hexA + " *a.tar.gz\r\n" + hexB + " *b.tar.gz\r\n", hexB},
		{"windows line ends, the first file", "a.tar.gz", hexA + "  a.tar.gz\r\n" + hexB + "  b.tar.gz\r\n", hexA},
		{"windows line ends, binary, the first file", "a.tar.gz", hexA + " *a.tar.gz\r\n" + hexB + " *b.tar.gz\r\n", hexA},
		{"windows line ends, a file in the middle", "mtg-2.2.8-linux-arm64.tar.gz", strings.ReplaceAll(mtgSums, "\n", "\r\n"), "562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644"},
		{"a path from the current directory", "a.tar.gz", hexA + "  ./a.tar.gz\n", hexA},
		{"a name with spaces", "my file.tar.gz", hexA + "  my file.tar.gz\n", hexA},
		{"a name that starts with a star", "*a.tar.gz", hexA + "  *a.tar.gz\n", hexA},
		{"upper-case digits are folded", "a.tar.gz", strings.ToUpper(hexA) + "  a.tar.gz\n", hexA},
		{"mixed case", "a.tar.gz", strings.ToUpper(hexA[:30]) + hexA[30:] + " *a.tar.gz\n", hexA},
		{"blank lines and other lines around", "a.tar.gz", "\n# sums of 3.5.13\n\n" + hexB + "  b.tar.gz\n\n" + hexA + "  a.tar.gz\n\ntrailing words\n", hexA},
		{"the same sum twice", "a.tar.gz", hexA + "  a.tar.gz\n" + hexA + " *a.tar.gz\n", hexA},
		{"the same sum twice, in two cases", "a.tar.gz", hexA + "  a.tar.gz\n" + strings.ToUpper(hexA) + "  a.tar.gz\n", hexA},

		// A file that holds only the sum.
		{"a lone sum", "anything.tar.gz", hexA + "\n", hexA},
		{"a lone sum without a newline", "anything.tar.gz", hexA, hexA},
		{"a lone sum with spaces and blank lines around", "x", "\n  " + hexA + "  \r\n\n", hexA},
		{"a lone sum in upper case", "x", strings.ToUpper(hexA) + "\n", hexA},
		{"a lone sum and an empty name", "", hexA + "\n", hexA},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := release.SumFor(tc.file, []byte(tc.data), release.SumsSHA256)
			if err != nil {
				t.Fatalf("SumFor: %v", err)
			}
			if got != tc.want {
				t.Errorf("SumFor = %s, want %s", got, tc.want)
			}
		})
	}

	// The sums that the plan pins agree with the files of the releases.
	if got, err := release.SumFor(telemtARM64, []byte(hexB+"  "+telemtARM64+"\n"), release.SumsSHA256); err != nil || got != hexB {
		t.Errorf("telemt arm64: %q, %v", got, err)
	}
}

func sumForNoSum(t *testing.T) {
	tests := []struct {
		name string
		file string
		data string
	}{
		{"not in the list", "mtg-2.2.8-linux-riscv64.tar.gz", mtgSums},
		{"another version", "mtg-2.2.7-linux-amd64.tar.gz", mtgSums},
		{"a name that is the start of another", "mtg-2.2.8-linux-amd64", mtgSums},
		{"a name that is the end of another", "linux-amd64.tar.gz", mtgSums},
		{"a name that is inside another", "amd64", mtgSums},
		{"a longer name", "mtg-2.2.8-linux-amd64.tar.gz.sha256", mtgSums},
		{"another case", "MTG-2.2.8-LINUX-AMD64.TAR.GZ", mtgSums},
		{"a name that is the hash", hexA, mtgSums},
		{"empty", "a", ""},
		{"nil-like blank", "a", "  \n\r\n\t\n"},
		{"an empty name that no line has", "", mtgSums},
		{"another name in the file", "b.tar.gz", hexA + "  a.tar.gz\n"},
		{"a page of html", "a.tar.gz", "<!DOCTYPE html>\n<html><head><title>404</title></head>\n<body>Not Found</body></html>\n"},
		{"a page of text with one line", "a.tar.gz", "404: Not Found\n"},
		{"a single space is not a separator", "a.tar.gz", hexA + " a.tar.gz\n"},
		{"a single space does not take a letter of the name for a mode", ".tar.gz", hexA + " a.tar.gz\n"},
		{"the star of the binary mode is not part of the name", "*a.tar.gz", hexA + " *a.tar.gz\n"},
		{"the second space of the text mode is not part of the name", " a.tar.gz", hexA + "  a.tar.gz\n"},
		{"a tab is not a separator", "a.tar.gz", hexA + "\ta.tar.gz\n"},
		{"the name before the sum", "a.tar.gz", "a.tar.gz  " + hexA + "\n"},
		{"no name", "a.tar.gz", hexA + "  \n" + hexB + "  b.tar.gz\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := release.SumFor(tc.file, []byte(tc.data), release.SumsSHA256)
			if !errors.Is(err, release.ErrNoSum) {
				t.Errorf("SumFor = %q, %v, want ErrNoSum", got, err)
			}
			if got != "" {
				t.Errorf("SumFor returned %q along with its error", got)
			}
		})
	}
}

// sumForRefused is a checksum file that names the file but cannot be trusted
// for it: an error, and not ErrNoSum, which would let a caller go on to the next
// source.
func sumForRefused(t *testing.T) {
	sha1 := hexA[:40]
	sha512 := hexA + hexB
	tests := []struct {
		name string
		file string
		data string
		f    release.SumsFormat
	}{
		{"two sums for one name", "a.tar.gz", hexA + "  a.tar.gz\n" + hexB + "  a.tar.gz\n", release.SumsSHA256},
		{"two sums, the other way round", "a.tar.gz", hexB + "  a.tar.gz\n" + hexA + "  a.tar.gz\n", release.SumsSHA256},
		{"two sums in the two modes", "a.tar.gz", hexA + "  a.tar.gz\n" + hexB + " *a.tar.gz\n", release.SumsSHA256},
		{"two sums with the other file between them", "a.tar.gz", hexA + "  a.tar.gz\n" + hexA + "  b.tar.gz\n" + hexB + "  a.tar.gz\n", release.SumsSHA256},
		{"two sums that differ in one digit", "a.tar.gz", hexA + "  a.tar.gz\n" + hexA[:63] + "4  a.tar.gz\n", release.SumsSHA256},
		{"a sum of 40 digits (SHA-1)", "a.tar.gz", sha1 + "  a.tar.gz\n", release.SumsSHA256},
		{"a sum of 128 digits (SHA-512)", "a.tar.gz", sha512 + "  a.tar.gz\n", release.SumsSHA256},
		{"a sum of 63 digits", "a.tar.gz", hexA[:63] + "  a.tar.gz\n", release.SumsSHA256},
		{"a sum of 65 digits", "a.tar.gz", hexA + "0  a.tar.gz\n", release.SumsSHA256},
		{"a sum of 64 characters that are not all digits", "a.tar.gz", hexA[:63] + "g  a.tar.gz\n", release.SumsSHA256},
		{"a sum with a prefix", "a.tar.gz", "sha256:" + hexA + "  a.tar.gz\n", release.SumsSHA256},
		{"a sum with 0x", "a.tar.gz", "0x" + hexA[2:] + "  a.tar.gz\n", release.SumsSHA256},
		{"a good sum after a bad one", "a.tar.gz", sha1 + "  a.tar.gz\n" + hexA + "  a.tar.gz\n", release.SumsSHA256},
		{"a lone sum of 63 digits", "a.tar.gz", hexA[:63] + "\n", release.SumsSHA256},
		{"a lone sum of 65 digits", "a.tar.gz", hexA + "0\n", release.SumsSHA256},
		{"a lone sum of 128 digits", "a.tar.gz", sha512 + "\n", release.SumsSHA256},
		{"a lone sum that is not hex", "a.tar.gz", strings.Repeat("z", 64) + "\n", release.SumsSHA256},
		{"a lone word", "a.tar.gz", "404\n", release.SumsSHA256},

		{"dgst: two different sums", "", "SHA2-256= " + hexA + "\nSHA2-256= " + hexB + "\n", release.SumsDgst},
		{"dgst: a sum of 40 digits", "", "SHA2-256= " + hexA[:40] + "\n", release.SumsDgst},
		{"dgst: a sum of 128 digits", "", "SHA2-256= " + hexA + hexB + "\n", release.SumsDgst},
		{"dgst: an empty sum", "", "SHA2-256= \n", release.SumsDgst},
		{"dgst: no sum at all after the sign", "", "SHA2-256=\n", release.SumsDgst},
		{"dgst: a sum that is not hex", "", "SHA2-256= " + strings.Repeat("x", 64) + "\n", release.SumsDgst},
		{"dgst: a good sum after a bad one", "", "SHA2-256= nope\nSHA2-256= " + hexA + "\n", release.SumsDgst},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := release.SumFor(tc.file, []byte(tc.data), tc.f)
			if err == nil {
				t.Fatalf("SumFor = %q, want an error", got)
			}
			if errors.Is(err, release.ErrNoSum) {
				t.Errorf("err = %v: a file that is there but cannot be trusted is not one that has no sum", err)
			}
			if got != "" {
				t.Errorf("SumFor returned %q along with its error", got)
			}
		})
	}
}

func sumForDgst(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		// gitleaks takes the word "xray" and a 64-digit hex for a JFrog token; this is
		// the public SHA-256 of an asset of Xray-core (the proxy), as the file says.
		{"xray, four lines", xrayDgst, "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"}, // gitleaks:allow
		{"warp-plus, three lines", warpDgst, "380d2c8655b33db818adf407c706d52d14c2ab1764e702e91f356a7d7d9c3c98"},
		{"the sum alone", "SHA2-256= " + hexA + "\n", hexA},
		{"no newline at the end", "SHA2-256= " + hexA, hexA},
		{"windows line ends", strings.ReplaceAll(xrayDgst, "\n", "\r\n"), "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"},
		{"no space after the sign", "SHA2-256=" + hexA + "\n", hexA},
		{"spaces around the sign", "SHA2-256 = " + hexA + "\n", hexA},
		{"more spaces", "SHA2-256=   " + hexA + "   \n", hexA},
		{"upper case is folded", "SHA2-256= " + strings.ToUpper(hexA) + "\n", hexA},
		{"the same sum twice", "SHA2-256= " + hexA + "\nMD5= 00\nSHA2-256= " + strings.ToUpper(hexA) + "\n", hexA},
		{"the last line", "MD5= x\nSHA1= y\nSHA2-512= " + hexA + hexB + "\nSHA2-256= " + hexB, hexB},
		{"the first line, after blank lines", "\n\nSHA2-256= " + hexB + "\nSHA2-512= " + hexA + hexB + "\n", hexB},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The file of one asset does not name it: the name is not used.
			for _, name := range []string{"", "Xray-linux-64.zip", "another.zip"} {
				got, err := release.SumFor(name, []byte(tc.data), release.SumsDgst)
				if err != nil {
					t.Fatalf("SumFor(%q): %v", name, err)
				}
				if got != tc.want {
					t.Errorf("SumFor(%q) = %s, want %s", name, got, tc.want)
				}
			}
		})
	}

	t.Run("no SHA2-256", func(t *testing.T) {
		for name, data := range map[string]string{
			"empty":                                "",
			"blank":                                "\n\n",
			"other digests only":                   "MD5= ee4e2ff74948a9b464624b1cabc44409\nSHA1= b55b06e74e89083b9cedfdecf0d68b579cd2af72\nSHA2-512= " + hexA + hexB + "\n",
			"a sha256sum file":                     hexA + "  a.tar.gz\n",
			"a lone sum":                           hexA + "\n",
			"the sum is a value of another digest": "SHA2-512= " + hexA + "\n",
			"the digest is named in the value":     "MD5= SHA2-256= " + hexA + "\n",
			"a page of html":                       "<html><body>404</body></html>\n",
		} {
			t.Run(name, func(t *testing.T) {
				got, err := release.SumFor("x", []byte(data), release.SumsDgst)
				if !errors.Is(err, release.ErrNoSum) {
					t.Errorf("SumFor = %q, %v, want ErrNoSum", got, err)
				}
			})
		}
	})
}

func sumForUnknownFormat(t *testing.T) {
	for _, f := range []release.SumsFormat{-1, 2, 99} {
		got, err := release.SumFor("a.tar.gz", []byte(hexA+"  a.tar.gz\n"), f)
		if err == nil || errors.Is(err, release.ErrNoSum) {
			t.Errorf("SumFor(format %d) = %q, %v, want an error that says the format is unknown", int(f), got, err)
		}
	}
}

func sumForErrorsDoNotQuoteTheFile(t *testing.T) {
	// A checksum file comes from the net, and an error goes to a log: what is
	// in the file is not put into the message.
	const junk = "JUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNK"
	// The right length and the wrong one, a sum that is a line and one that is a file.
	for _, tc := range []struct {
		data string
		f    release.SumsFormat
	}{
		{junk + "  a.tar.gz\n", release.SumsSHA256},
		{junk + "\n", release.SumsSHA256},
		{"SHA2-256= " + junk + "\n", release.SumsDgst},
		{junk[:40] + "  a.tar.gz\n", release.SumsSHA256},
		{junk[:40] + "\n", release.SumsSHA256},
		{"SHA2-256= " + junk[:40] + "\n", release.SumsDgst},
		{junk + junk + "  a.tar.gz\n", release.SumsSHA256},
		{junk + junk + "\n", release.SumsSHA256},
		{"SHA2-256= " + junk + junk + "\n", release.SumsDgst},
		{hexA + "  a.tar.gz\n" + junk + "  a.tar.gz\n", release.SumsSHA256},
		{hexA + "  a.tar.gz\n" + hexB + "  a.tar.gz\n", release.SumsSHA256},
	} {
		_, err := release.SumFor("a.tar.gz", []byte(tc.data), tc.f)
		if err == nil {
			t.Fatalf("SumFor(%q) succeeded", tc.data)
		}
		if strings.Contains(err.Error(), "JUNK") {
			t.Errorf("err = %q quotes the file", err)
		}
	}
}
