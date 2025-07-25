package vault

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptAndSaveVault(t *testing.T) {

	t.Run("Empty Credentials", func(t *testing.T) {

		MEK := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, MEK); err != nil {
			t.Fatalf("Could not generate a MEK %v", err.Error())
		}

		err := EncryptAndSaveVault(nil, MEK)
		if err != nil {
			t.Errorf("Test Failed. %v", err.Error())
		}

	})
}
