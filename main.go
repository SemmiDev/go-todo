package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/semmidev/auth-service/token"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var googleOauthConfig *oauth2.Config

func init() {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		ClientID:     "26803728727-4mecc7j32s5kg21gj4n5n7t2pnorkkkh.apps.googleusercontent.com",
		ClientSecret: "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",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func main() {
	r := chi.NewRouter()

	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Heartbeat("/ping"))

	symmetricKey := "12345678901234567890123456789012"
	token, err := token.NewPasetoMaker(symmetricKey)
	if err != nil {
		log.Fatalf("failed to create token maker: %v", err)
	}

	fs := http.FileServer(http.Dir("./static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fs))

	handlers := &handlers{
		userStore: NewUserMapStore(),
		tokenMaker: token,
	}

	r.Handle("/", http.HandlerFunc(handlers.HomePage))
	r.With(AuthMiddleware(token)).Handle("/profile", http.HandlerFunc(handlers.ProfilePage))

	r.Get("/logout", handlers.handleLogout)
	r.Get("/auth/login", handlers.handleGoogleLogin)
	r.Get("/auth/google/callback", handlers.handleGoogleCallback)

	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

type handlers struct {
	userStore *UserMapStore
	tokenMaker token.Maker
}

func (h *handlers) HomePage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("views/index.html"))
	tmpl.Execute(w, nil)
}

func (h *handlers) ProfilePage(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value(authorizationPayloadKey).(*token.Payload)
	user, _ := h.userStore.GetByEmail(payload.Email)

	tmpl := template.Must(template.ParseFiles("views/profile.html"))
	tmpl.Execute(w, user)
}

func (h *handlers) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *handlers) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Error exchanging code for token", http.StatusBadRequest)
		return
	}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		http.Error(w, "Error getting user info", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		http.Error(w, "Error decoding user info", http.StatusBadRequest)
		return
	}

	userInfoStruct := User{
		ID: userInfo["id"].(string),
		Email: userInfo["email"].(string),
		FamilyName: userInfo["family_name"].(string),
		GivenName: userInfo["given_name"].(string),
		Locale: userInfo["locale"].(string),
		Name: userInfo["name"].(string),
		Picture: userInfo["picture"].(string),
		VerifiedEmail: userInfo["verified_email"].(bool),
	}

	err = h.userStore.Insert(userInfoStruct)
	if err != nil {
		if err != ErrorUserExists {
			log.Printf("failed to insert user: %v", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		}
	}

	duration := time.Hour * 24 * 30
	pasetoToken, _, err := h.tokenMaker.CreateToken(userInfoStruct.Email, duration)
	if err != nil {
		log.Printf("failed to create token: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	cookie := http.Cookie{
		Path:    "/",
		Name:    "access_token",
		Value:   pasetoToken,
		Expires: time.Now().Add(duration),
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/profile", http.StatusTemporaryRedirect)
}

func (h *handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Path:    "/",
		Name: "access_token",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
