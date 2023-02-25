package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/mail"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/semmidev/go-todo/auth"
	"github.com/semmidev/go-todo/token"
	"golang.org/x/oauth2"
)

//go:embed views/*
var Resources embed.FS

//go:embed public
var StaticFiles embed.FS

func fsHandler() http.Handler {
    sub, err := fs.Sub(StaticFiles, "public")
    if err != nil {
        panic(err)
    }

    return http.FileServer(http.FS(sub))
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

	r.Get("/public/*", http.StripPrefix("/public", fsHandler()).ServeHTTP)

	handlers := &handlers{
		userStore: NewUserMapStore(),
		todoStore: NewTodoMapStore(),
		tokenMaker: token,
		embed: Resources,
	}

	r.With(auth.MustLoginMiddleware(token)).Handle("/", http.HandlerFunc(handlers.handleHomePage))

	r.Get("/login", handlers.handleLoginPage)
	r.Get("/auth/login", handlers.handleGoogleLogin)
	r.Get("/auth/google/callback", handlers.handleGoogleCallback)
	r.Get("/logout", handlers.handleLogout)

	r.With(auth.MustLoginMiddleware(token)).Handle("/todos/search", http.HandlerFunc(handlers.handleSearchTodos))
	r.With(auth.MustLoginMiddleware(token)).Handle("/profile", http.HandlerFunc(handlers.handleProfilePage))
	r.Get("/login", handlers.handleLoginPage)

	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

type handlers struct {
	userStore  UserStore
	todoStore  TodoStore
	tokenMaker token.Maker
	embed      embed.FS
}

func (h *handlers) handleHomePage(w http.ResponseWriter, r *http.Request) {
	homePage := path.Join("views","index.html")
	tmpl := template.Must(template.ParseFS(h.embed, homePage))
	err := tmpl.Execute(w, nil)
	if err != nil {
		err := newErrorPage("Internal server error", http.StatusInternalServerError)
		h.handleErrorPage(w, r, err)
		return
	}
}

func (h *handlers) handleSearchTodos(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value(auth.AuthorizationPayloadKey).(*token.Payload)
	user, err := h.userStore.GetByEmail(payload.Email)
	if err != nil {
		err := newErrorPage("User not found", http.StatusNotFound)
		h.handleErrorPage(w, r, err)
		return
	}

	q := r.URL.Query().Get("q")

	todos := h.todoStore.Search(user.ID, q)
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(todos)
	if err != nil {
		err := newErrorPage("Internal server error", http.StatusInternalServerError)
		h.handleErrorPage(w, r, err)
		return
	}
}

func (h *handlers) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// if user has already logged in, redirect to home page
	cookie, err := r.Cookie("access_token")
	if err == nil {
		accessToken := cookie.Value
		_, err := h.tokenMaker.VerifyToken(accessToken)
		if err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	loginPage := path.Join("views","login.html")
	tmpl := template.Must(template.ParseFS(h.embed, loginPage))
	err = tmpl.Execute(w, nil)
	if err != nil {
		err := newErrorPage("Internal server error", http.StatusInternalServerError)
		h.handleErrorPage(w, r, err)
		return
	}
}

func (h *handlers) handleProfilePage(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value(auth.AuthorizationPayloadKey).(*token.Payload)
	user, err := h.userStore.GetByEmail(payload.Email)
	if err != nil {
		err := newErrorPage("User not found", http.StatusNotFound)
		h.handleErrorPage(w, r, err)
		return
	}

	profilePage := path.Join("views","profile.html")
	tmpl := template.Must(template.ParseFS(h.embed, profilePage))
	err = tmpl.Execute(w, user)
	if err != nil {
		err := newErrorPage("Internal server error", http.StatusInternalServerError)
		h.handleErrorPage(w, r, err)
		return
	}
}

func (h *handlers) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := auth.GoogleOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *handlers) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := auth.GoogleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		err := newErrorPage("Error exchanging code for token", http.StatusBadRequest)
		h.handleErrorPage(w, r, err)
		return
	}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		err := newErrorPage("Error getting user info", http.StatusBadRequest)
		h.handleErrorPage(w, r, err)
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		err := newErrorPage("Error decoding user info", http.StatusBadRequest)
		h.handleErrorPage(w, r, err)
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

	acceptedEmail := validateEmail(userInfoStruct.Email)
	if !acceptedEmail {
		err := newErrorPage("Please use university email", http.StatusBadRequest)
		h.handleErrorPage(w, r, err)
		return
	}

	err = h.userStore.Insert(userInfoStruct)
	if err != nil {
		if err != ErrorUserExists {
			err := newErrorPage("Internal server error", http.StatusInternalServerError)
			h.handleErrorPage(w, r, err)
			return
		}
	}

	h.todoStore.Seed(userInfoStruct.ID)

	duration := time.Hour * 24 * 30
	pasetoToken, _, err := h.tokenMaker.CreateToken(userInfoStruct.Email, duration)
	if err != nil {
		err := newErrorPage("Internal server error", http.StatusInternalServerError)
		h.handleErrorPage(w, r, err)
		return
	}

	cookie := http.Cookie{
		Path:    "/",
		Name:    "access_token",
		Value:   pasetoToken,
		Expires: time.Now().Add(duration),
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (h *handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Path:    "/",
		Name: "access_token",
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

func (h *handlers) handleErrorPage(w http.ResponseWriter, r *http.Request, data any) {
	errorPage := path.Join("views","error.html")
	tmpl := template.Must(template.ParseFS(h.embed, errorPage))
	err := tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func newErrorPage(message string, code int) map[string]any {
	return map[string]any{
		"Message": message,
		"Code": code,
	}
}

func validateEmail(email string) bool {
    _, err := mail.ParseAddress(email)
    if err != nil {
        return false
    }

    parts := strings.Split(email, "@")
    if len(parts) != 2 {
        return false
    }
    domain := parts[1]

	return domain == "student.unri.ac.id" || domain == "lecturer.unri.ac.id"
}
