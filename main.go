package main

import (
	"PasswordManager/controller"
	"PasswordManager/vault"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var globalApp controller.App

type SignupRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
type AuthResponse struct {
	Message     string `json:"message"`
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirectUrl,omitempty"` // Add an optional redirect URL field
}

func main() {
	globalApp = *controller.NewApp()

	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./web"))
	mux.Handle("/", fs)

	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/signup", handleSignup)
	mux.HandleFunc("/api/signin", handleSignin)
	mux.HandleFunc("/api/signout", handleSignout)
	mux.HandleFunc("/api/credentials", handleCredentials)
	mux.HandleFunc("/api/add-credential", handleAddCredential)

	port := 8080

	fmt.Printf("Server starting on http://localhost:%v\n", port)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), mux))

}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	var status bool
	if globalApp.CurrentUser == nil {
		status = false
	} else {
		status = true
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"logstatus": status})
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	if globalApp.CurrentUser != nil {
		http.Redirect(w, r, "/api/vault", 302)
		return
	}
	if r.Method == http.MethodGet {
		htmlContent, _ := os.ReadFile("./web/index.html")
		injected := strings.Replace(string(htmlContent), "</head>", `<script> window.initialFormType = 'signup';</script></head>`, 1)
		w.Write([]byte(injected))
		return
	} else if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		var signupData SignupRequest
		json.Unmarshal(body, &signupData)
		err := globalApp.SignUp(signupData.Username, signupData.Password)
		if err != nil {
			http.Error(w, "Something went wrong", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AuthResponse{RedirectURL: "/index.html/?form=signin", Success: true})

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(fmt.Sprintf("This is %v Signup", r.Method)))
	}
}
func handleAddCredential(w http.ResponseWriter, r *http.Request) {

	var status bool
	if globalApp.CurrentUser == nil {
		status = false
	} else {
		status = true
	}

	if !status {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	var newUser vault.Credential
	err := json.Unmarshal(body, &newUser)
	if err != nil {
		http.Error(w, "Something went wrong", 405)
		return
	}
	err = globalApp.AddCredential(newUser.URL, newUser.Username, newUser.Password)
	if err != nil {
		http.Error(w, "Something went wrong", 405)
		return
	}

	w.WriteHeader(http.StatusOK)
	return
}
func handleCredentials(w http.ResponseWriter, r *http.Request) {

	var status bool
	if globalApp.CurrentUser == nil {
		status = false
	} else {
		status = true
	}

	if !status {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(globalApp.DecryptedVault)
}

func handleSignin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		htmlContent, _ := os.ReadFile("./web/index.html")
		injected := strings.Replace(string(htmlContent), "</head>", `<script> window.initialFormType = 'signin';</script></head>`, 1)
		w.Write([]byte(injected))
		return
	} else if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		var signupData SignupRequest
		json.Unmarshal(body, &signupData)
		err := globalApp.SignIn(signupData.Username, signupData.Password)
		if err != nil {
			http.Error(w, "Something went wrong", 400)
			return
		}
		w.WriteHeader(http.StatusCreated)                                                                                           // 201 Created
		json.NewEncoder(w).Encode(AuthResponse{Message: "User signed up successfully!", Success: true, RedirectURL: "/vault.html"}) // Include redirect URL
		return
	}
}

func handleSignout(w http.ResponseWriter, r *http.Request) {
	if globalApp.CurrentUser != nil {
		globalApp.SignOut()
	}

	json.NewEncoder(w).Encode(AuthResponse{Success: true, RedirectURL: "/index.html/?form=signin"})
}
