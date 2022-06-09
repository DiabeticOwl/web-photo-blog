package main

import (
	"html/template"
	"net/http"
	"time"

	"web-photo-blog/user"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type session struct {
	un           string
	lastActivity time.Time
}

var tpl *template.Template

// UserName, User
var dbUsers = make(map[string]user.User)

// Session ID, UserName
var dbSessions = make(map[string]session)

const (
	sessionLength int = 30
)

func init() {
	tpl = template.Must(template.ParseGlob("./templates/*.gohtml"))
}

func main() {
	// dbUsers, err := user.AllUsers()
	// if err != nil {
	// 	panic(err)
	// }

	// TODO: Add Login and Log out.

	http.HandleFunc("/", index)
	http.HandleFunc("/signup/", signUp)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, req *http.Request) {
	tpl.ExecuteTemplate(w, "index.gohtml", nil)
}

func signUp(w http.ResponseWriter, r *http.Request) {
	if alreadyLoggedIn(w, r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		un := r.FormValue("username")
		pw := r.FormValue("password")
		fn := r.FormValue("firstname")
		ln := r.FormValue("lastname")

		// More validations would be appropriate.
		if un == "" || pw == "" || fn == "" || ln == "" {
			http.Error(w,
				"Please fill all fields before proceeding through the SignUp.",
				http.StatusBadRequest)

			return
		}

		isSigned := user.IsSigned(user.SearchUser(un))

		if isSigned {
			http.Error(w,
				"The submitted username is already in use.",
				http.StatusForbidden)

			return
		}

		sID := uuid.New().String()
		saltPass := uuid.New().String()

		c := &http.Cookie{
			Name:     "session",
			Value:    sID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   sessionLength,
		}

		http.SetCookie(w, c)
		dbSessions[c.Value] = session{
			un:           un,
			lastActivity: time.Now(),
		}

		// Encrypting password with bcrypt.
		sb, err := bcrypt.GenerateFromPassword(
			[]byte(saltPass+pw),
			bcrypt.DefaultCost,
		)
		if err != nil {
			http.Error(w,
				"Internal Server Error",
				http.StatusInternalServerError)

			// Put panic instead of return since this error might be not very
			// clear so panic will help more in debugging.
			panic(err)
		}

		u := user.User{
			UserName:  un,
			SaltPass:  saltPass,
			Password:  sb,
			FirstName: fn,
			LastName:  ln,
		}
		err = user.AddUser(u)
		if err != nil {
			http.Error(w,
				"Internal Server Error",
				http.StatusInternalServerError)

			panic(err)
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	tpl.ExecuteTemplate(w, "signup.gohtml", nil)
}
