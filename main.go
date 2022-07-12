package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	"github.com/lestrrat-go/jwx/jwt"
)

func main() {
	port := "8080"

	if fromEnv := os.Getenv(
		"PORT"); fromEnv != "" {
		port = fromEnv
	}

	log.Printf("Starting up on http://localhost:%s", port)

	log.Fatal(http.ListenAndServe(":"+port, router()))
}

var tokenAuth *jwtauth.JWTAuth

const Secret = "jwt-secret"

func init() {
	tokenAuth = jwtauth.New(
		"HS256", []byte(Secret), nil)
}

func router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)

	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))

		r.Get("/", func(
			w http.ResponseWriter,
			r *http.Request) {
			// ...
		})
	})

	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))

		r.Use(LoggedInRedirector)

		r.Get("/login",
			func(w http.ResponseWriter,
				r *http.Request) {
				// ...
			})
	})

	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))

		r.Use(UnloggedInRedirector)

		r.Get("/profile",
			func(w http.ResponseWriter,
				r *http.Request) {
				tmpl, data := ParseTemplates(
					r, []string{
						"partials/navbar.html",
						"pages/profile.html"})

				tmpl.ExecuteTemplate(
					w,
					"profile",
					data)
			})
	})

	r.Group(func(r chi.Router) {
		r.Post("/login", func(
			w http.ResponseWriter,
			r *http.Request) {
			r.ParseForm()
			userName := r.PostForm.Get("username")
			userPassword := r.PostForm.Get("password")

			if userName == "" || userPassword == "" {
				http.Error(
					w,
					"Missing username or password.",
					http.StatusBadRequest)
				return
			}

			token := MakeToken(userName)

			http.SetCookie(w, &http.Cookie{
				HttpOnly: true,
				Expires: time.Now().
					Add(7 * 24 * time.Hour),
				SameSite: http.SameSiteLaxMode,
				// Uncomment below for HTTPS:
				// Secure: true,
				Name:  "jwt",
				Value: token,
			})

			http.Redirect(
				w, r, "/profile",
				http.StatusSeeOther)
		})

		r.Post("/logout", func(
			w http.ResponseWriter,
			r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				HttpOnly: true,
				MaxAge:   -1, // Delete the cookie.
				SameSite: http.SameSiteLaxMode,
				// Uncomment below for HTTPS:
				// Secure: true,
				Name:  "jwt",
				Value: "",
			})

			http.Redirect(w, r,
				"/", http.StatusSeeOther)
		})
	})
}

func MakeToken(name string) string {
	_, tokenString, _ := tokenAuth.Encode(map[string]interface{}{"username": name})
	return tokenString
}

func LoggedInRedirector(
	next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter,
			r *http.Request) {
			token, _, _ := jwtauth.FromContext(r.Context())

			if token != nil && jwt.Validate(
				token) == nil {
				http.Redirect(
					w,
					r,
					"/profile", 302)
			}

			next.ServeHTTP(w, r)
		})
}

func UnloggedInRedirector(
	next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter,
			r *http.Request) {
			token, _, _ := jwtauth.FromContext(r.Context())

			if token == nil || jwt.Validate(
				token) != nil {
				http.Redirect(
					w,
					r,
					"/login", 302)
			}

			next.ServeHTTP(w, r)
		})
}

type User struct {
	Username string
}

type PageData struct {
	User *User
}

func ParseTemplates(
	r *http.Request,
	templates []string) (*template.Template, *PageData) {
	_, claims, _ := jwtauth.FromContext(r.Context())

	tmpl := template.Must(
		template.ParseFiles(templates...))

	data := &PageData{
		User: nil,
	}

	if claims["username"] != nil {
		data.User = &User{
			Username: claims["username"].(string),
		}
	}

	return tmpl, data
}
