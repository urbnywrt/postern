// Package seal keeps secrets safe at rest. The panel uses it to encrypt the
// secrets that it stores in its database (TOTP secrets, private keys) with a
// master key that lives in a file of its own, so that a copy of the database
// alone reveals none of them.
//
// A sealed value is
//
//	0x01 || nonce (12 bytes) || ciphertext || tag (16 bytes)
//
// where 0x01 is the version of the format, and the nonce, the ciphertext and the
// tag are the output of AES-256-GCM. The nonce is random, and one key can seal up
// to 2^32 values with random nonces (NIST SP 800-38D, section 8.3), far more
// than the panel stores.
//
// The additional data that the caller passes (aad) is authenticated but not
// stored: the same bytes have to be given to open the value. It ties a value to
// the place that it is kept in, for example "totp:<admin id>", so that a sealed
// value that is copied into another row or column does not open there.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	keySize     = 32
	version1    = 0x01
	nonceSize   = 12
	tagSize     = 16
	minSealedSz = 1 + nonceSize + tagSize // a sealed empty plaintext
)

// Key is an AES-256 key. It is key material, so do not log or print it.
type Key [keySize]byte

var (
	// ErrMalformed is returned by [Open] for a value that is too short to be a
	// sealed value.
	ErrMalformed = errors.New("seal: malformed sealed value")

	// ErrVersion is returned by [Open] for a value of a version that this package
	// does not know.
	ErrVersion = errors.New("seal: unknown version of sealed value")

	// ErrDecrypt is returned by [Open] when the key is not the one that sealed
	// the value, the additional data differs, or the value was changed. These
	// cannot be told apart.
	ErrDecrypt = errors.New("seal: cannot decrypt: wrong key, wrong additional data, or the value was changed")
)

// Seal encrypts and authenticates plaintext with k and returns the sealed value.
// The aad is authenticated as well and has to be given to [Open] again; it may
// be nil.
func Seal(k Key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(k)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1, minSealedSz+len(plaintext))
	out[0] = version1
	// The AEAD makes the nonce and puts it in front of the ciphertext.
	return aead.Seal(out, nil, plaintext, aad), nil
}

// Open returns the plaintext of a value that [Seal] made with the same key and
// aad. It returns [ErrMalformed], [ErrVersion] or [ErrDecrypt], and no
// plaintext, for a value that cannot be opened.
func Open(k Key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < minSealedSz {
		return nil, ErrMalformed
	}
	if sealed[0] != version1 {
		return nil, ErrVersion
	}
	aead, err := newAEAD(k)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nil, sealed[1:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// newAEAD returns AES-256-GCM that makes its own random nonces and puts them in
// front of the ciphertext.
func newAEAD(k Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return aead, nil
}

// LoadOrCreateKey returns the master key that is stored in the file at path,
// and makes the key first if the file does not exist.
//
// A new key is 32 bytes from crypto/rand. Its file can be read and written by
// its owner only (0600), and the directories that have to be created for it
// have mode 0700. A directory that already exists keeps its mode, and so does a
// key file that already exists: operators restore keys from backups and mount
// them from secret stores.
//
// A file that exists must hold exactly 32 bytes. Anything else is an error, and
// the file is left alone, since it may hold a real key in another form (hex,
// base64, with a line break) that must not be overwritten. A symbolic link is
// followed when the key is read.
//
// If the process stops after the file was created but before the key was
// written, the next call refuses the short file, which is safe to delete: no
// value has been sealed with that key yet.
//
// Keep a copy of the key apart from the database. Without it the sealed values
// cannot be opened.
func LoadOrCreateKey(path string) (Key, error) {
	k, err := loadKey(path)
	if !errors.Is(err, fs.ErrNotExist) {
		return k, err
	}
	k, err = createKey(path)
	if errors.Is(err, fs.ErrExist) {
		// The file appeared after the check above, or the path is a link to
		// nothing, which is an error to report rather than a file to replace.
		return loadKey(path)
	}
	return k, err
}

func loadKey(path string) (Key, error) {
	f, err := os.Open(path)
	if err != nil {
		return Key{}, fmt.Errorf("seal: key file: %w", err)
	}
	defer func() { _ = f.Close() }() // the file was only read

	info, err := f.Stat()
	if err != nil {
		return Key{}, fmt.Errorf("seal: key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Key{}, fmt.Errorf("seal: key file %s is not a regular file", path)
	}

	// One byte more than a key tells a file that is too long from one that fits.
	var buf [keySize + 1]byte
	n, err := io.ReadFull(f, buf[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return Key{}, fmt.Errorf("seal: key file: %w", err)
	}
	if n != keySize {
		found := fmt.Sprintf("%d bytes", n)
		if n > keySize {
			found = fmt.Sprintf("more than %d bytes", keySize)
		}
		return Key{}, fmt.Errorf("seal: key file %s must hold exactly %d bytes, it holds %s; the file was not changed", path, keySize, found)
	}

	var k Key
	copy(k[:], buf[:keySize])
	clear(buf[:])
	return k, nil
}

func createKey(path string) (Key, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Key{}, fmt.Errorf("seal: key directory: %w", err)
	}

	var k Key
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return Key{}, fmt.Errorf("seal: generate key: %w", err)
	}

	// O_EXCL: never write into a file that is there already.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Key{}, fmt.Errorf("seal: key file: %w", err)
	}
	_, err = f.Write(k[:])
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path) // do not leave a short file behind
		return Key{}, fmt.Errorf("seal: key file: %w", err)
	}
	syncDir(dir)
	return k, nil
}

// syncDir flushes the entry of a new file to disk. Not every system can flush a
// directory, and the file itself is flushed already, so an error is ignored.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
