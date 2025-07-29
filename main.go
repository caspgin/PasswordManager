package main

import (
	"PasswordManager/controller"
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

func main() {
	globalApp = *controller.NewApp()

	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./web"))
	mux.Handle("/", fs)

	mux.HandleFunc("/api/signup", handleSignup)
	mux.HandleFunc("/api/signin", handleSignin)
	mux.HandleFunc("/api/signout", handleSignout)
	mux.HandleFunc("/api/credentials", handleCredentials)
	mux.HandleFunc("/api/add-credential", handleAddCredential)

	port := 8080

	fmt.Printf("Server starting on http://localhost:%v\n", port)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), mux))

}

func handleSignup(w http.ResponseWriter, r *http.Request) {
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
			log.Printf("Error Signing up, %v", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Signup successful!"})

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(fmt.Sprintf("This is %v Signup", r.Method)))
	}
}
func handleAddCredential(w http.ResponseWriter, r *http.Request) {

}
func handleCredentials(w http.ResponseWriter, r *http.Request) {

}
func handleSignin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		htmlContent, _ := os.ReadFile("./web/index.html")
		injected := strings.Replace(string(htmlContent), "</head>", `<script> window.initialFormType = 'signin';</script></head>`, 1)
		w.Write([]byte(injected))
		return
	} else if r.Method == http.MethodPost {

	}
}

func handleSignout(w http.ResponseWriter, r *http.Request) {

}
