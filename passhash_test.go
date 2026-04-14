package passhash

import (
	"strings"
	"testing"
)

func TestMakePassword(t *testing.T) {
	hash, err := MakePassword("correcthorse", 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify modular crypt format: $pbkdf2-sha512$<iter>$<salt>$<hash>
	tokens := strings.Split(hash, "$")
	if len(tokens) != 5 {
		t.Fatalf("expected 5 $-delimited tokens, got %d: %q", len(tokens), hash)
	}
	if tokens[0] != "" {
		t.Errorf("expected empty first token (leading $), got %q", tokens[0])
	}
	if tokens[1] != algorithmID {
		t.Errorf("expected algorithm %q, got %q", algorithmID, tokens[1])
	}
	if tokens[2] != "210000" {
		t.Errorf("expected default iteration 210000, got %q", tokens[2])
	}
	if tokens[3] == "" {
		t.Error("salt token is empty")
	}
	if tokens[4] == "" {
		t.Error("hash token is empty")
	}
}

func TestMakePasswordCustomIteration(t *testing.T) {
	hash, err := MakePassword("password", 50000, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokens := strings.Split(hash, "$")
	if tokens[2] != "50000" {
		t.Errorf("expected iteration 50000, got %q", tokens[2])
	}
}

func TestMakePasswordCustomSalt(t *testing.T) {
	hash, err := MakePassword("password", 0, "mysalt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same password + salt + iterations should produce identical hash
	hash2, err := MakePassword("password", 0, "mysalt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != hash2 {
		t.Errorf("identical inputs produced different hashes:\n  %s\n  %s", hash, hash2)
	}
}

func TestMakePasswordEmptyPassword(t *testing.T) {
	_, err := MakePassword("", 0, "")
	if err == nil {
		t.Fatal("expected error for empty password, got nil")
	}
}

func TestMakePasswordUniqueSalts(t *testing.T) {
	hash1, err := MakePassword("password", 1000, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hash2, err := MakePassword("password", 1000, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash1 == hash2 {
		t.Error("two calls with empty salt produced identical hashes; salts should be unique")
	}
}

func TestCheckPasswordRoundTrip(t *testing.T) {
	password := "correct horse battery staple"
	hash, err := MakePassword(password, 1000, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ok, err := CheckPassword(password, hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("CheckPassword returned false for correct password")
	}
}

func TestCheckPasswordWrongPassword(t *testing.T) {
	hash, err := MakePassword("rightpassword", 1000, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ok, err := CheckPassword("wrongpassword", hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("CheckPassword returned true for wrong password")
	}
}

func TestCheckPasswordMalformedHash(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"empty string", ""},
		{"no delimiters", "notahash"},
		{"too few tokens", "$pbkdf2-sha512$1000$salt"},
		{"too many tokens", "$pbkdf2-sha512$1000$salt$hash$extra"},
		{"bad iteration", "$pbkdf2-sha512$notanumber$c2FsdA$aGFzaA"},
		{"bad algorithm", "$scrypt$1000$c2FsdA$aGFzaA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CheckPassword("password", tt.hash)
			if err == nil {
				t.Errorf("expected error for hash %q, got nil", tt.hash)
			}
		})
	}
}

func TestCheckPasswordBadBase64Salt(t *testing.T) {
	_, err := CheckPassword("password", "$pbkdf2-sha512$1000$!!!invalid$aGFzaA")
	if err == nil {
		t.Fatal("expected error for invalid base64 salt, got nil")
	}
}

func TestCheckPasswordBadBase64Hash(t *testing.T) {
	_, err := CheckPassword("password", "$pbkdf2-sha512$1000$c2FsdA$!!!invalid")
	if err == nil {
		t.Fatal("expected error for invalid base64 hash, got nil")
	}
}

func TestB64RoundTrip(t *testing.T) {
	original := []byte("test data with various bytes: \x00\xff\x80")
	encoded := b64Encode(original)
	decoded, err := b64Decode(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("round-trip failed: got %q, want %q", decoded, original)
	}
}

func TestB64EncodeNoPlusCharacter(t *testing.T) {
	// Find input that produces '+' in standard base64
	// 0xfb => base64 has '+' in standard encoding
	input := []byte{0xfb, 0xff}
	encoded := b64Encode(input)
	if strings.Contains(encoded, "+") {
		t.Errorf("b64Encode output contains '+': %q", encoded)
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := generateSalt(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(salt1) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(salt1))
	}

	salt2, err := generateSalt(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(salt1) == string(salt2) {
		t.Error("two consecutive salts are identical")
	}
}

func BenchmarkMakePassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = MakePassword("benchmarkpassword", 1000, "benchmarksalt")
	}
}

func BenchmarkCheckPassword(b *testing.B) {
	hash, _ := MakePassword("benchmarkpassword", 1000, "benchmarksalt")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CheckPassword("benchmarkpassword", hash)
	}
}
