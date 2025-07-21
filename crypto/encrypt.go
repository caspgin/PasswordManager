package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

func Encrypt(MEK []byte) error {
	var (
		cipherBlock cipher.Block
		err         error
	)

	//Get the cipher.Block interface to be used in GCM
	cipherBlock, err = aes.NewCipher(MEK)
	if err != nil {
		var e string = "Error from new cipher: " + err.Error()
		return errors.New(e)
	}

	//gcm, err := cipher.NewGCM(cipherBlock)

	return nil
}

func GetDerivedKey(masterPassword []byte, salt []byte, iteration int) []byte {
	return pbkdf2.Key(masterPassword, salt, iteration, 32, sha256.New)
}
