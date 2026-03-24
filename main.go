package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/mattn/go-sqlite3"
	//"golang.org/x/text/message"
)

var db *sql.DB

func init() {
	db, _ = sql.Open("sqlite3", "./test.db")
}

type RESET struct {
	token string `json:"token"`
	email string `json:"email"`
}
type User struct {
	Username string
}

func doesExistsUsername(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	var exists int
	err := db.QueryRow(
		"SELECT 1 FROM Users WHERE username=?",
		username,
	).Scan(&exists)

	if err == sql.ErrNoRows {
		fmt.Fprintf(w, "0")
	} else {
		fmt.Fprintf(w, "1")
	}
}
func loginHandler(w http.ResponseWriter, r *http.Request) {

	user := r.FormValue("username")
	pass := r.FormValue("password")
	message := "Wrong username"

	var dbPass string
	err := db.QueryRow(
		"SELECT password FROM Users WHERE username=?",
		user,
	).Scan(&dbPass)
	fmt.Print(err)

	if err == nil {

		if bcrypt.CompareHashAndPassword([]byte(dbPass), []byte(pass)) == nil {

			message = "1"

			bytes := make([]byte, 16)
			rand.Read(bytes)
			session := hex.EncodeToString(bytes)
			db.Exec("DELETE FROM session WHERE username=?", user)
			_, err := db.Exec(
				"INSERT INTO session(username, session) VALUES(?,?)",
				user,
				session,
			)

			if err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:  "session",
					Value: session,
				})
			}

		} else {
			message = "Wrong password"
		}
	}

	fmt.Fprintf(w, message)
}
func LoginpageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "template/login.html")
}

// func ResetHandler(w http.ResponseWriter, r *http.Request){

// }
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if len(r.Form) > 0 {
		token := r.FormValue("token")
		if token == "0" {
			username := r.FormValue("username")
			password := r.FormValue("password")
			email := r.FormValue("email")
			bytes := make([]byte, 16)
			rand.Read(bytes)
			token = hex.EncodeToString(bytes)
			db.Exec("INSERT INTO token (token, username, password,email) VALUES (?, ?, ?, ?)", token, username, password, email)
			fmt.Fprintf(w, token)
			fmt.Print(token)
			return
		}
		dbtoken := ""
		dbusername := ""
		dbpassword := ""
		dbemail := ""
		err := db.QueryRow("SELECT token, username, password, email FROM token WHERE token=?", token).Scan(&dbtoken, &dbusername, &dbpassword, &dbemail)
		if err != nil {
			fmt.Fprintf(w, "Invalid token")
			return
		} else {
			hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(dbpassword), bcrypt.DefaultCost)
			db.Exec("INSERT INTO Users (username, password, email) VALUES (?, ?, ?)", dbusername, string(hashedPassword), dbemail)
			db.Exec("DELETE FROM token WHERE token=?", token)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		return
	}
	http.ServeFile(w, r, "template/signup.html")
}
func HomepageHandler(w http.ResponseWriter, r *http.Request) {
	tmp := template.Must(template.ParseFiles("template/index.html"))
	c, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	session := c.Value
	row := db.QueryRow("SELECT username FROM session WHERE session=?", session)
	var username string
	err = row.Scan(&username)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	Username := User{Username: username}
	tmp.Execute(w, Username)
}
func resetHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("reset handler called")
	username := r.FormValue("username")
	password := r.FormValue("password")
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	var email string
	db.QueryRow("SELECT email FROM Users WHERE username=?", username).Scan(&email)
	bytes := make([]byte, 16)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)
	db.Exec("INSERT INTO reset (username, token, password) VALUES (?, ?, ?)", username, token, string(hashedPassword))
	en, _ := json.Marshal(RESET{token: token, email: email})
	fmt.Println(string(en))
	fmt.Fprintf(w, string(en))
}
func resetPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "template/reset_page.html")
}
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: "",
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func newPassHandler(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	var username string
	var password string
	err := db.QueryRow("SELECT username,password FROM reset WHERE token=?", token).Scan(&username, &password)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	} else {
		db.Exec("DELETE FROM reset WHERE token=?", token)
		db.Exec("UPDATE Users SET password=? WHERE username=?", password, username)
		fmt.Fprintf(w, "Password reset successful. You can now log in with your new password.")
	}
}
func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", LoginpageHandler)
	http.HandleFunc("/home", HomepageHandler)
	http.HandleFunc("/signup", SignupHandler)
	http.HandleFunc("/check_username", doesExistsUsername)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/reset_page", resetPageHandler)
	http.HandleFunc("/reset_password", resetHandler)
	http.HandleFunc("/reset", newPassHandler) // Handle the reset page access
	http.ListenAndServe(":8080", nil)

}
