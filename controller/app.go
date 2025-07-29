package controller

import (
	"PasswordManager/crypto"
	"PasswordManager/user"
	"PasswordManager/vault"
	"fmt"
)

type App struct {
	CurrentUser    *user.User
	DecryptedVault []vault.Credential
	IsVaultLoaded  bool
	key            []byte
}

func NewApp() *App {
	return &App{}
}

func (app *App) SignUp(username string, password string) error {
	//Check if user Exists
	recievedUser, err := user.GetUser(username)

	if err != nil {
		return fmt.Errorf("something went wrong %w", err)
	}
	if recievedUser != nil {
		return fmt.Errorf("User %q already exist", username)
	}
	//Generate a new Salt
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("Something went wrong. Could not create user. %w", err)
	}
	//Save the User to user_data.json
	newUser := user.User{
		Username:   username,
		MasterSalt: salt,
	}
	err = user.SaveUser(&newUser)

	if err != nil {
		return fmt.Errorf("Something went wrong. Could not create user. %w", err)
	}

	MEK := crypto.GetDerivedKey([]byte(password), newUser.MasterSalt, 100096)

	err = vault.EncryptAndSaveVault(nil, MEK)

	if err != nil {
		return fmt.Errorf("Encryption Failed. %w", err)
	}

	return nil
}

func (app *App) SignIn(username string, password string) error {
	app.IsVaultLoaded = false
	var err error

	//Get user
	app.CurrentUser, err = user.GetUser(username)
	if err != nil {
		return fmt.Errorf("User %q does not Exist.: %v", username, err.Error())
	}

	//Deruve Key from user Salt and input password
	app.key = crypto.GetDerivedKey([]byte(password), app.CurrentUser.MasterSalt, 100096)

	//Decrypt Vault
	app.DecryptedVault, err = vault.LoadAndDecryptVault(app.key)
	if err != nil {
		return fmt.Errorf("Decryption Failed. %w", err)
	}

	app.IsVaultLoaded = true
	return nil
}

func (app *App) SignOut() {
	app.key = nil
	app.DecryptedVault = nil
	app.CurrentUser = nil
	app.IsVaultLoaded = false
}

func (app *App) AddCredential(url string, username string, password string) error {

	app.DecryptedVault = append(app.DecryptedVault, vault.Credential{URL: url, Username: username, Password: password})

	err := vault.EncryptAndSaveVault(app.DecryptedVault, app.key)
	if err != nil {
		app.DecryptedVault[len(app.DecryptedVault)-1] = vault.Credential{}
		app.DecryptedVault = app.DecryptedVault[0 : len(app.DecryptedVault)-1]
		return fmt.Errorf("Could not add credentials. %w", err)
	}
	return nil
}

func (app *App) GetCredentialsForDisplay() []vault.Credential {
	if !app.IsVaultLoaded {
		return nil
	}
	return app.DecryptedVault
}
