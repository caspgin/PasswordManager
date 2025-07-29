package vault

import (
	"PasswordManager/crypto"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

//Create Credential

const appName string = "Pharoas"
const vaultName string = "default.vault"

type Credential struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Vault struct

type Vault struct {
	iv            []byte
	encryptedData []byte
}

func ReadVault(filePath string) ([]byte, error) {
	cipherText, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("File %q could not be read : %w", filePath, err)
	}
	return cipherText, nil
}

func getVault() (string, error) {

	appDir, err := GetAppConfigDir()
	if err != nil {
		return "", fmt.Errorf("Could not get the App directory. %w", err)
	}
	filePath := path.Join(appDir, vaultName)

	if exist, _ := vaultExist(filePath); exist != true {
		CreateVault(filePath)
	}
	return filePath, nil
}

func WriteVault(cipherText []byte) error {
	filePath, err := getVault()
	if err != nil {
		return fmt.Errorf("Could not get Vault. %w.", err)
	}
	err = os.WriteFile(filePath, cipherText, 0644)
	if err != nil {
		return fmt.Errorf("Writing to Vault Failed. Vault File Deleted. %w", err)
	}
	return nil
}

func vaultExist(filePath string) (bool, error) {

	_, err := os.Stat(filePath)
	if err == nil {
		if filepath.Ext(filePath) == ".vault" {
			return true, nil
		}
		return false, fmt.Errorf("File %q is not the write type or is a directory", filePath)
	}

	return false, fmt.Errorf("File %q does not exist : %w", filePath, err)
}

func CreateVault(filePath string) error {
	os.Create(filePath)
	return nil
}

func GetAppConfigDir() (string, error) {

	baseDir := os.Getenv("AppData")
	appDir := filepath.Join(baseDir, appName)
	err := os.MkdirAll(appDir, 0700)
	if err != nil {
		return "", fmt.Errorf("failed to create application directory %q: %w", appDir, err)
	}

	return appDir, nil
}

func LoadAndDecryptVault(MEK []byte) ([]Credential, error) {
	//Get the Vault
	vaultPath, err := getVault()
	if err != nil {
		return nil, fmt.Errorf("Loading Vault failed. %w", err)
	}
	//Read Vault
	cipherText, err := ReadVault(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("Loading Vault Failed. %w", err)
	}

	//Decrypt it using key
	decryptedData, err := crypto.Decrypt(MEK, cipherText)
	if err != nil {
		return nil, fmt.Errorf("Loading Vault failed. %w", err)
	}

	if len(decryptedData) == 0 {
		return []Credential{}, nil
	}
	//Unmarshall
	var credentials []Credential
	err = json.Unmarshal(decryptedData, &credentials)
	if err != nil {
		return nil, fmt.Errorf("Loading Vault Failed.error marshalling %w", err)
	}

	return credentials, nil
}

func EncryptAndSaveVault(credentials []Credential, MEK []byte) error {
	//Marshall the Credentials into json
	jsonData, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("Could not Encrypt and Save the credentials %w:", err)
	}
	//Encrypt the jsonData using the MasterEncryptionKey(MEK) and you recieve
	//{
	// nonce		Intialization Vector in []byte
	// cipherText	EncryptedData in []byte
	// err			if any
	//}
	nonce, cipherText, err := crypto.Encrypt(MEK, jsonData)
	if err != nil {
		return fmt.Errorf("Could not Encrypt and Save the credentials %w:", err)
	}
	//combine nonce and ciphertext
	nonce = append(nonce, cipherText...)

	//Write to Vault File
	err = WriteVault(nonce)

	if err != nil {
		return fmt.Errorf("Could not Encrypt and Save the credentials %w:", err)
	}
	return nil
}
