package auth_test

import (
	"strings"
	"testing"

	"github.com/Florencea/erp-rbac/internal/auth"
)

func TestHashAndVerifyPasswordFormatAndUniqueness(t *testing.T) {
	t.Parallel()

	if _, err := auth.HashPassword(""); err == nil {
		t.Fatal("expected error when hashing empty password")
	}

	h1, err := auth.HashPassword("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password 1: %v", err)
	}
	h2, err := auth.HashPassword("StrongPass123!")
	if err != nil {
		t.Fatalf("hash password 2: %v", err)
	}

	if !strings.HasPrefix(h1, "$pbkdf2-sha512$i=210000$") {
		t.Fatalf("unexpected PHC prefix: %q", h1)
	}
	if h1 == h2 {
		t.Fatal("expected distinct random salts to produce distinct password hashes")
	}
	if !auth.VerifyPassword(h1, "StrongPass123!") || !auth.VerifyPassword(h2, "StrongPass123!") {
		t.Fatal("expected both hashes to verify matching password")
	}
	if auth.VerifyPassword(h1, "WrongPass123!") {
		t.Fatal("expected verification failure for wrong password")
	}
	if auth.VerifyPassword(h1, "") {
		t.Fatal("expected verification failure for empty password")
	}
}

func TestPasswordBeyond72BytesNotTruncated(t *testing.T) {
	t.Parallel()

	prefix := strings.Repeat("a", 72)
	passA := prefix + "-suffix-A"
	passB := prefix + "-suffix-B"

	hash, err := auth.HashPassword(passA)
	if err != nil {
		t.Fatalf("hash long password: %v", err)
	}
	if !auth.VerifyPassword(hash, passA) {
		t.Fatal("expected exact long password to verify")
	}
	if auth.VerifyPassword(hash, passB) {
		t.Fatal("expected password differing after byte 72 to fail verification")
	}
}

func TestVerifyPasswordRejectsMalformedAndLegacyHashes(t *testing.T) {
	t.Parallel()

	validHash, err := auth.HashPassword("StrongPass123!")
	if err != nil {
		t.Fatalf("hash valid password: %v", err)
	}
	parts := strings.Split(validHash, "$")
	tamperedDK := parts[4]
	if tamperedDK[0] == 'A' {
		tamperedDK = "B" + tamperedDK[1:]
	} else {
		tamperedDK = "A" + tamperedDK[1:]
	}
	tamperedHash := strings.Join([]string{parts[0], parts[1], parts[2], parts[3], tamperedDK}, "$")

	cases := []struct {
		name string
		hash string
	}{
		{name: "empty", hash: ""},
		{name: "legacy bcrypt", hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"},
		{name: "missing parts", hash: "$pbkdf2-sha512$i=210000$onlysalt"},
		{name: "extra parts", hash: validHash + "$extra"},
		{name: "unknown algorithm", hash: "$pbkdf2-sha256$i=210000$" + parts[3] + "$" + parts[4]},
		{name: "missing iteration prefix", hash: "$pbkdf2-sha512$210000$" + parts[3] + "$" + parts[4]},
		{name: "iterations below minimum", hash: "$pbkdf2-sha512$i=1000$" + parts[3] + "$" + parts[4]},
		{name: "iterations above maximum", hash: "$pbkdf2-sha512$i=99999999$" + parts[3] + "$" + parts[4]},
		{name: "invalid base64 salt", hash: "$pbkdf2-sha512$i=210000$!!!$" + parts[4]},
		{name: "short salt", hash: "$pbkdf2-sha512$i=210000$c2hvcnQ$" + parts[4]},
		{name: "short key", hash: "$pbkdf2-sha512$i=210000$" + parts[3] + "$c2hvcnQ"},
		{name: "tampered digest", hash: tamperedHash},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if auth.VerifyPassword(tc.hash, "StrongPass123!") {
				t.Fatalf("expected VerifyPassword to reject %s hash", tc.name)
			}
		})
	}
}
