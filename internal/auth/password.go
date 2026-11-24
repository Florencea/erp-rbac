package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	pbkdf2Algorithm     = "pbkdf2-sha512"
	pbkdf2Iterations    = 210_000
	pbkdf2MinIterations = 100_000
	pbkdf2MaxIterations = 10_000_000
	pbkdf2SaltBytes     = 16
	pbkdf2KeyBytes      = 32
)

// HashPassword hashes a plaintext password with PBKDF2-HMAC-SHA512 using a random 128-bit salt.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("password must not be empty")
	}

	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	dk, err := pbkdf2.Key(sha512.New, plain, salt, pbkdf2Iterations, pbkdf2KeyBytes)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"$%s$i=%d$%s$%s",
		pbkdf2Algorithm,
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

// VerifyPassword compares a stored PBKDF2-HMAC-SHA512 PHC hash against a plaintext password in constant time.
func VerifyPassword(hashed, plain string) bool {
	if hashed == "" || plain == "" {
		return false
	}

	parts := strings.Split(hashed, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != pbkdf2Algorithm {
		return false
	}

	iterStr, ok := strings.CutPrefix(parts[2], "i=")
	if !ok {
		return false
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter < pbkdf2MinIterations || iter > pbkdf2MaxIterations {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < pbkdf2SaltBytes {
		return false
	}

	expectedDK, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(expectedDK) < pbkdf2KeyBytes {
		return false
	}

	derived, err := pbkdf2.Key(sha512.New, plain, salt, iter, len(expectedDK))
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(derived, expectedDK) == 1
}
