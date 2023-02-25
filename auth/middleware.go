package auth

import (
	"context"
	"net/http"

	"github.com/semmidev/go-todo/token"
)

type AuthorizationType string

var	AuthorizationPayloadKey AuthorizationType  = "authorization_payload"

func MustLoginMiddleware(token token.Maker) func(http.Handler) http.Handler {
	f := func(h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("access_token")
			if err != nil {
				http.Redirect(w, r, "/logout", http.StatusSeeOther)
				return
			}

			accessToken := cookie.Value

			payload, err := token.VerifyToken(accessToken)
			if err != nil {
				http.Redirect(w, r, "/logout", http.StatusSeeOther)
				return
			}

			ctx := context.WithValue(r.Context(), AuthorizationPayloadKey, payload)
			h.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
	return f
}
