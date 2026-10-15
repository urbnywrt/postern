package release

// The tests need to put keys where the production keys are compiled in, and to
// shrink the size limit of legacy signatures. These functions are compiled into
// the test binary only.

// SetProductionKeys replaces the compiled-in production key lists of the two
// key sets and returns the function that puts the old lists back. It must not
// be called while a verification is under way.
func SetProductionKeys(releaseKeys, stableKeys string) (restore func()) {
	oldRelease, oldStable := productionReleaseKeys, productionStableKeys
	productionReleaseKeys, productionStableKeys = releaseKeys, stableKeys
	return func() { productionReleaseKeys, productionStableKeys = oldRelease, oldStable }
}

// SetExtraPublicKeys replaces the keys that a build adds with
// -ldflags -X ...release.extraPublicKeys and returns the function that puts the
// old value back.
func SetExtraPublicKeys(keys string) (restore func()) {
	old := extraPublicKeys
	extraPublicKeys = keys
	return func() { extraPublicKeys = old }
}

// SetMaxLegacyBytes sets the largest input that VerifyWith accepts under a
// legacy signature (the real limit is 64 MiB, too much to fill in a test) and
// returns the function that puts the old limit back.
func SetMaxLegacyBytes(n int64) (restore func()) {
	old := maxLegacyBytes
	maxLegacyBytes = n
	return func() { maxLegacyBytes = old }
}

// MaxLegacyBytes returns the current limit that SetMaxLegacyBytes sets.
func MaxLegacyBytes() int64 { return maxLegacyBytes }
