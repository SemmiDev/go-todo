package main

import (
	"context"
	"net/http"

	"github.com/semmidev/auth-service/token"
)

type authorizationType string

func (at authorizationType) String() string {
	return string(at)
}

const (
	authorizationHeaderKey authorizationType  = "authorization"
	authorizationTypeBearer authorizationType = "bearer"
	authorizationPayloadKey authorizationType = "authorization_payload"
)

func AuthMiddleware(token token.Maker) func(http.Handler) http.Handler {
	f := func(h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("access_token")
			if err != nil {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			accessToken := cookie.Value

			payload, err := token.VerifyToken(accessToken)
			if err != nil {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			ctx := context.WithValue(r.Context(), authorizationPayloadKey, payload)
			h.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
	return f
}
