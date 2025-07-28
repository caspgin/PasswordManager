package user

import (
	"PasswordManager/vault"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

const UserFileName string = "user_data.json"

type User struct {
	Username   string `json:"username"`
	MasterSalt []byte `json:"master_salt"`
}

func GetAllUsers() ([]User, error) {

	filePath, err := getUserFilePath()
	if err != nil {
		return nil, fmt.Errorf("Cannot get users: %w", err)
	}
	//Read `json"`
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("Cannot Read user file. %v", err.Error())
	}
	var users []User = nil
	err = json.Unmarshal(bytes, &users)
	if err != nil {
		return nil, fmt.Errorf("Cannot Read user file. %w", err)
	}
	return users, nil
}

func GetUser(username string) (*User, error) {

	users, err := GetAllUsers()
	if err != nil {
		return nil, fmt.Errorf("Cannot save users: %w", err)
	}

	//Search for username
	for _, user := range users {
		if user.Username == username {
			return &user, nil
		}
	}
	return nil, nil
}

func SaveUser(user *User) error {
	//Read the user JSon file
	users, err := GetAllUsers()
	if err != nil {
		return fmt.Errorf("Cannot save users: %w", err)
	}

	//Append the new user
	users = append(users, *user)

	// marshall into `json:`
	bytes, err := json.Marshal(users)
	if err != nil {
		return fmt.Errorf("Cannot Write user file. %w", err)
	}
	//Get the user_data file
	filePath, err := getUserFilePath()
	if err != nil {
		return fmt.Errorf("Cannot Save user with name %q : %w", user.Username, err)
	}
	//Write to file
	os.WriteFile(filePath, bytes, 0755)
	return nil
}

func getUserFilePath() (string, error) {
	appDir, err := vault.GetAppConfigDir()
	if err != nil {
		return "", fmt.Errorf("Could not get AppDirectory. %w", err)
	}
	userFilePath := path.Join(appDir, UserFileName)
	_, err = os.Stat(userFilePath)
	if err == nil {
		return userFilePath, nil
	}

	_, err = CreateFileWithDirs(userFilePath)
	if err != nil {
		return "", err
	}
	return userFilePath, nil
}

func CreateFileWithDirs(filePath string) (*os.File, error) {
	// 1. Get the directory part of the file path
	dir := filepath.Dir(filePath)

	// 2. Create the directory (and any necessary parent directories) if it doesn't exist
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create directory '%s': %w", dir, err)
	}

	// 3. Create/Open the file
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create or open file '%s': %w", filePath, err)
	}
	var t string = "[]"
	_, err = file.Write([]byte(t))
	if err != nil {
		file.Close()
		os.Remove(filePath)
		return nil, fmt.Errorf("Could not make a file %w", err)
	}

	file.Close()
	return file, nil
}
