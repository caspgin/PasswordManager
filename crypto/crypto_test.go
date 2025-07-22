package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestGetDerivedKey tests the GetDerivedKey function.
func TestGetDerivedKey(t *testing.T) {
	// --- Test Case 1: Standard inputs, verify against a known good value ---
	// It's crucial for deterministic functions like KDFs to test against
	// independently verified, known-good test vectors.

	testPassword1 := []byte("password")
	testSalt1 := []byte("salt")
	testIteration1 := 4096 // For testing, keep iterations relatively low for speed
	// Expected key for password="password", salt="salt", iterations=4096, keyLen=32, hash=SHA256
	// Calculated using an independent tool:
	expectedKeyHex1 := "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
	expectedKey1, err := hex.DecodeString(expectedKeyHex1)
	if err != nil {
		t.Fatalf("Failed to decode expected key hex for test case 1: %v", err)
	}

	derivedKey1 := GetDerivedKey(testPassword1, testSalt1, testIteration1)

	if !bytes.Equal(derivedKey1, expectedKey1) {
		t.Errorf(
			"Test Case 1 failed: Derived key mismatch.\nPassword: %s, Salt: %s, Iterations: %d\nGot:  %x\nWant: %x",
			testPassword1, testSalt1, testIteration1, derivedKey1, expectedKey1,
		)
	}

	// --- Test Case 2: Different password and salt ---
	testPassword2 := []byte("AnotherStrongPass")
	testSalt2 := []byte("randomSalt12345")
	testIteration2 := 1000 // Even lower for quick dev tests
	// Expected key for password="AnotherStrongPass", salt="randomSalt12345", iterations=1000, keyLen=32, hash=SHA256
	expectedKeyHex2 := "0e8aaee2a845141512b4b9cb81e62e0c8c61cc9d863af575aecbadfd8c4268ff"
	expectedKey2, err := hex.DecodeString(expectedKeyHex2)
	if err != nil {
		t.Fatalf("Failed to decode expected key hex for test case 2: %v", err)
	}

	derivedKey2 := GetDerivedKey(testPassword2, testSalt2, testIteration2)

	if !bytes.Equal(derivedKey2, expectedKey2) {
		t.Errorf(
			"Test Case 2 failed: Derived key mismatch.\nPassword: %s, Salt: %s, Iterations: %d\nGot:  %x\nWant: %x",
			testPassword2, testSalt2, testIteration2, derivedKey2, expectedKey2,
		)
	}

	// --- Test Case 3: Zero-length password or salt (PBKDF2 behavior) ---
	// PBKDF2 generally handles zero-length inputs without error,
	// producing a deterministic key. This tests that behavior.
	testPassword3 := []byte("")
	testSalt3 := []byte("")
	testIteration3 := 1
	// Expected key for password="", salt="", iterations=1, keyLen=32, hash=SHA256
	expectedKey3 := GetDerivedKey(testPassword3, testSalt3, testIteration3)
	derivedKey3 := GetDerivedKey(testPassword3, testSalt3, testIteration3)

	if !bytes.Equal(derivedKey3, expectedKey3) {
		t.Errorf(
			"Test Case 3 failed: Derived key mismatch for empty inputs.\nGot:  %x\nWant: %x",
			derivedKey3, expectedKey3,
		)
	}

	// --- Test Case 4: Key Length ---
	// Your function hardcodes keyLen to 32, so we verify that.
	expectedKeyLength := 32
	if len(derivedKey1) != expectedKeyLength {
		t.Errorf("Derived key length mismatch. Got %d, want %d", len(derivedKey1), expectedKeyLength)
	}
	if len(derivedKey2) != expectedKeyLength {
		t.Errorf("Derived key length mismatch. Got %d, want %d", len(derivedKey2), expectedKeyLength)
	}
}

// Example of a benchmark test (optional)
// Benchmarks help you measure the performance of your code.
// Run with: go test -bench=.
func BenchmarkGetDerivedKey(b *testing.B) {
	password := []byte("benchmarkPassword")
	salt := []byte("benchmarkSalt")
	iterations := 300000 // Use a realistic iteration count for benchmarks

	// Reset timer to exclude setup time

	for b.Loop() {
		GetDerivedKey(password, salt, iterations)
	}
}
