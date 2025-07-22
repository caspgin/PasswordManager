package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Performs AES256-GCM Encrytion on data using MasterEncryptionKey(MEK)
func Encrypt(MEK []byte, data []byte) ([]byte, []byte, error) {
	var (
		cipherBlock cipher.Block
		err         error
	)

	//Get the cipher.Block interface to be used in GCM
	cipherBlock, err = aes.NewCipher(MEK)
	if err != nil {
		var e string = "Encryption Failed: " + err.Error()
		return nil, nil, errors.New(e)
	}

	//GCM Mode of Operation for AES gives us the AREAD
	aesGCM, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, nil, errors.New("Encryption Failed: " + err.Error())
	}
	//Allocating NonceSize() length to a slice and assigning to nonce
	nonce := make([]byte, aesGCM.NonceSize())
	//Generating a CyrptoGraphically Secure Psuedo Random number which io reads from rand to nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, errors.New("Encryption Failed: " + err.Error())
	}

	cipherText := aesGCM.Seal(nil, nonce, data, nil)

	return nonce, cipherText, nil
}

func Decrypt(MEK []byte, nonce []byte, cipherText []byte) ([]byte, error) {

	cipherBlock, err := aes.NewCipher(MEK)
	if err != nil {
		var e string = "Decryption Failed: " + err.Error()
		return nil, errors.New(e)
	}

	//GCM Mode of Operation for AES gives us the AREAD
	aesGCM, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, errors.New("Decryption Failed: " + err.Error())
	}

	data, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, errors.New("Decryption and/or Authentication Failed: " + err.Error())
	}
	return data, nil
}

func GetDerivedKey(masterPassword []byte, salt []byte, iteration int) []byte {
	return pbkdf2.Key(masterPassword, salt, iteration, 32, sha256.New)
}
