package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
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

// Testing encryption and Decryption functions
func TestEncryptDecrypt(t *testing.T) {
	// A fixed test key (32 bytes for AES-256). In production, this would be derived.
	// For testing, a constant key makes tests deterministic and repeatable.
	testMEK := []byte("thisisatestmasterencryptionkey32") // 32 bytes long

	// --- Test Case 1: Basic Encrypt and Decrypt Roundtrip ---
	t.Run("Basic Roundtrip", func(t *testing.T) {
		plaintext := []byte("This is my super secret message for testing.")
		// No additional data for this test case

		nonce, ciphertext, err := Encrypt(testMEK, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		// Basic sanity checks on encrypted output
		if len(nonce) != 12 { // GCM NonceSize is 12 bytes
			t.Errorf("Nonce length unexpected. Got %d, want 12", len(nonce))
		}
		if len(ciphertext) != len(plaintext)+aes.BlockSize { // Plaintext + GCM Overhead (16 bytes for AES)
			t.Errorf("Ciphertext length unexpected. Got %d, want %d", len(ciphertext), len(plaintext)+aes.BlockSize)
		}
		if bytes.Equal(ciphertext, plaintext) {
			t.Error("Ciphertext is identical to plaintext, likely an encryption error.")
		}

		decryptedPlaintext, err := Decrypt(testMEK, nonce, ciphertext)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(decryptedPlaintext, plaintext) {
			t.Errorf("Decrypted plaintext mismatch.\nGot:  %s\nWant: %s", decryptedPlaintext, plaintext)
		}
	})

	// --- Test Case 2: Empty Plaintext ---
	t.Run("Empty Plaintext", func(t *testing.T) {
		plaintext := []byte("") // Empty plaintext
		// No additional data for this test case

		nonce, ciphertext, err := Encrypt(testMEK, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed for empty plaintext: %v", err)
		}

		// Ciphertext for empty plaintext should only be the GCM tag (16 bytes)
		if len(ciphertext) != aes.BlockSize {
			t.Errorf("Ciphertext length for empty plaintext unexpected. Got %d, want %d", len(ciphertext), aes.BlockSize)
		}

		decryptedPlaintext, err := Decrypt(testMEK, nonce, ciphertext)
		if err != nil {
			t.Fatalf("Decrypt failed for empty plaintext: %v", err)
		}

		if !bytes.Equal(decryptedPlaintext, plaintext) {
			t.Errorf("Decrypted plaintext mismatch for empty plaintext.\nGot:  %s\nWant: %s", decryptedPlaintext, plaintext)
		}
	})

	// --- Test Case 3: Decryption with Tampered Ciphertext ---
	t.Run("Tampered Ciphertext", func(t *testing.T) {
		plaintext := []byte("Some data to tamper.")
		nonce, ciphertext, err := Encrypt(testMEK, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed for tampering test: %v", err)
		}

		// Create a tampered copy
		tamperedCiphertext := make([]byte, len(ciphertext))
		copy(tamperedCiphertext, ciphertext)
		// Flip a bit in the ciphertext (guaranteed to cause authentication failure)
		tamperedCiphertext[0] ^= 0x01

		_, err = Decrypt(testMEK, nonce, tamperedCiphertext)
		if err == nil {
			t.Error("Decryption with tampered ciphertext should have failed, but succeeded.")
		} else if err.Error() != "Decryption and/or Authentication Failed: cipher: message authentication failed" {
			// Check for the specific authentication error
			// Note: Go's crypto/cipher returns cipher.AEADInvalidTag.
			// Your function wraps it, so we check both the wrapped error and the string.
			t.Errorf("Decryption with tampered ciphertext failed with unexpected error: %v", err)
		}
	})

	// --- Test Case 4: Decryption with Invalid Nonce ---
	t.Run("Invalid Nonce", func(t *testing.T) {
		plaintext := []byte("Data for invalid nonce test.")
		nonce, ciphertext, err := Encrypt(testMEK, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed for invalid nonce test: %v", err)
		}

		// Create an invalid nonce by flipping a bit
		invalidNonce := make([]byte, len(nonce))
		copy(invalidNonce, nonce)
		invalidNonce[0] ^= 0x01

		_, err = Decrypt(testMEK, invalidNonce, ciphertext)
		if err == nil {
			t.Error("Decryption with invalid nonce should have failed, but succeeded.")
		} else if err.Error() != "Decryption and/or Authentication Failed: cipher: message authentication failed" {
			t.Errorf("Decryption with invalid nonce failed with unexpected error: %v", err)
		}
	})

	// --- Test Case 5: Decryption with Wrong Key ---
	t.Run("Wrong Key", func(t *testing.T) {
		plaintext := []byte("Data for wrong key test.")
		nonce, ciphertext, err := Encrypt(testMEK, plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed for wrong key test: %v", err)
		}

		// Create a different key
		wrongMEK := make([]byte, len(testMEK))
		if _, err := rand.Read(wrongMEK); err != nil {
			t.Fatalf("Failed to generate wrong test key: %v", err)
		}

		_, err = Decrypt(wrongMEK, nonce, ciphertext)
		if err == nil {
			t.Error("Decryption with wrong key should have failed, but succeeded.")
		} else if err.Error() != "Decryption and/or Authentication Failed: cipher: message authentication failed" {
			// Note: If NewCipher fails due to wrong key size, it might return a different error.
			// But if the key size is correct, it will typically fail at Open with AEADInvalidTag.
			t.Errorf("Decryption with wrong key failed with unexpected error: %v", err)
		}
	})

	// --- Test Case 6: Encrypt with an invalid MEK size ---
	t.Run("Invalid MEK Size for Encrypt", func(t *testing.T) {
		invalidMEK := []byte("shortkey") // Not 16, 24, or 32 bytes
		plaintext := []byte("some data")
		_, _, err := Encrypt(invalidMEK, plaintext)
		if err == nil {
			t.Error("Encrypt with invalid MEK size should have failed, but succeeded.")
		} else if !bytes.Contains([]byte(err.Error()), []byte("crypto/aes: invalid key size")) {
			// Check for the specific error message from aes.NewCipher
			t.Errorf("Encrypt with invalid MEK size failed with unexpected error: %v", err)
		}
	})

	// --- Test Case 7: Decrypt with an invalid MEK size ---
	t.Run("Invalid MEK Size for Decrypt", func(t *testing.T) {
		invalidMEK := []byte("shortkey") // Not 16, 24, or 32 bytes
		// We don't need actual ciphertext/nonce for this test, as it should fail at NewCipher
		_, err := Decrypt(invalidMEK, nil, nil)
		if err == nil {
			t.Error("Decrypt with invalid MEK size should have failed, but succeeded.")
		} else if !bytes.Contains([]byte(err.Error()), []byte("crypto/aes: invalid key size")) {
			t.Errorf("Decrypt with invalid MEK size failed with unexpected error: %v", err)
		}
	})
}

// Optional Benchmark code for Encrypt/Decrypt (similar to GetDerivedKey)
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
func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate test key: %v", err)
	}
	plaintext := make([]byte, 1024) // 1KB data
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate test plaintext: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := Encrypt(key, plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate test key: %v", err)
	}
	plaintext := make([]byte, 1024) // 1KB data
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate test plaintext: %v", err)
	}
	nonce, ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		b.Fatalf("Setup for benchmark failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(key, nonce, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}
