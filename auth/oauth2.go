package auth

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var GoogleOauthConfig *oauth2.Config

func init() {
	GoogleOauthConfig = &oauth2.Config{
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
