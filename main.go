package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/mattn/go-sqlite3"
	//"golang.org/x/text/message"
)

type User struct {
	Username string
}

func doesExistsUsername(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite3", "./test.db")
	username := r.FormValue("username")
	_, err := db.Exec("INSERT INTO Users (username, password) VALUES (?, ?)", username, "password")
	if err != nil {
		fmt.Fprintf(w, "1")
		return
	} else {
		db.Exec("DELETE FROM Users WHERE username=?", username)
		fmt.Fprintf(w, "0")
	}
}
func loginHandler(w http.ResponseWriter, r *http.Request) {

	user := r.FormValue("username")
	pass := r.FormValue("password")
	message := "Wrong username"

	db, _ := sql.Open("sqlite3", "./test.db")
	defer db.Close()

	var dbPass string
	err := db.QueryRow(
		"SELECT password FROM Users WHERE username=?",
		user,
	).Scan(&dbPass)

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
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		db, _ := sql.Open("sqlite3", "./test.db")
		defer db.Close()
		_, err := db.Exec("INSERT INTO Users (username, password) VALUES (?, ?)", username, string(hashedPassword))
		if err != nil {
			fmt.Fprintf(w, "Username already exists")
			return
		}
		fmt.Fprintf(w, "1")
		return
	}
	http.ServeFile(w, r, "template/signup.html")
}
func HomepageHandler(w http.ResponseWriter, r *http.Request) {
	tmp := template.Must(template.ParseFiles("template/index.html"))
	c, _ := r.Cookie("session")
	session := c.Value
	db, _ := sql.Open("sqlite3", "./test.db")
	row := db.QueryRow("SELECT username FROM session WHERE session=?", session)
	var username string
	row.Scan(&username)
	Username := User{Username: username}
	tmp.Execute(w, Username)
	db.Close()
}
func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", LoginpageHandler)
	http.HandleFunc("/home", HomepageHandler)
	http.HandleFunc("/signup", SignupHandler)
	http.HandleFunc("/check_username", doesExistsUsername)
	http.ListenAndServe(":8080", nil)
	// db, _ := sql.Open("sqlite3", "LOGIN_TEST/test.db")
	// hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	// db.Exec("INSERT INTO Users (username, password) VALUES (?, ?)", "admin", string(hashedPassword))

}
