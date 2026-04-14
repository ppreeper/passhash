// Package passhash provides password hashing and verification using PBKDF2-SHA512.
//
// Passwords are hashed into modular crypt format strings:
//
//	$pbkdf2-sha512$<iterations>$<salt>$<hash>
package passhash

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	pbkdf2lib "golang.org/x/crypto/pbkdf2"
)

const (
	// randomSize is the number of random bytes used for salt generation.
	randomSize = 16

	// iterationDefault is the default PBKDF2 iteration count.
	// OWASP (2023) recommends 600,000 for PBKDF2-SHA512; 210,000 is a
	// reasonable balance between security and performance.
	iterationDefault = 210000

	// algorithmID is the identifier written into the modular crypt format string.
	algorithmID = "pbkdf2-sha512"
)

// generateSalt returns randomSize cryptographically random bytes.
func generateSalt(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	return b, nil
}

func b64Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, ".", "+")
	return base64.RawStdEncoding.DecodeString(s)
}

func b64Encode(b []byte) string {
	s := base64.RawStdEncoding.EncodeToString(b)
	return strings.ReplaceAll(s, "+", ".")
}

// MakePassword derives a PBKDF2-SHA512 hash from the given password.
// If iteration is 0, the default iteration count is used.
// If salt is empty, a cryptographically random salt is generated.
// Returns a modular crypt format string: $pbkdf2-sha512$<iterations>$<salt>$<hash>.
func MakePassword(password string, iteration int, salt string) (string, error) {
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}
	if iteration == 0 {
		iteration = iterationDefault
	}

	var saltb []byte
	if len(salt) == 0 {
		var err error
		saltb, err = generateSalt(randomSize)
		if err != nil {
			return "", err
		}
	} else {
		saltb = []byte(salt)
	}

	key := pbkdf2lib.Key([]byte(password), saltb, iteration, sha512.Size, sha512.New)
	return fmt.Sprintf("$%s$%d$%s$%s", algorithmID, iteration, b64Encode(saltb), b64Encode(key)), nil
}

// CheckPassword verifies a plaintext password against a stored hash string.
// It returns true if the password matches, false otherwise.
// An error is returned if the hash string is malformed or cannot be parsed.
func CheckPassword(password string, passwordHash string) (bool, error) {
	tokens := strings.Split(passwordHash, "$")
	if len(tokens) != 5 {
		return false, fmt.Errorf("invalid hash format: expected 5 $-delimited tokens, got %d", len(tokens))
	}

	if tokens[1] != algorithmID {
		return false, fmt.Errorf("unsupported algorithm: %q (expected %q)", tokens[1], algorithmID)
	}

	iteration, err := strconv.Atoi(tokens[2])
	if err != nil {
		return false, fmt.Errorf("parsing iteration count: %w", err)
	}

	salt, err := b64Decode(tokens[3])
	if err != nil {
		return false, fmt.Errorf("decoding salt: %w", err)
	}

	storedHash, err := b64Decode(tokens[4])
	if err != nil {
		return false, fmt.Errorf("decoding hash: %w", err)
	}

	key := pbkdf2lib.Key([]byte(password), salt, iteration, sha512.Size, sha512.New)
	return subtle.ConstantTimeCompare(key, storedHash) == 1, nil
}
