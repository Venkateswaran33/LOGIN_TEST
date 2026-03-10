package main

import (
	"database/sql"
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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// if r.Method == "POST" {
	user := r.FormValue("username")
	pass := r.FormValue("password")
	message := "Wrong username"
	db, _ := sql.Open("sqlite3", "test.db")
	countRow, _ := db.Query("SELECT count(*) FROM users WHERE username=?", user)
	var count int
	countRow.Next()
	countRow.Scan(&count)
	countRow.Close()
	row, _ := db.Query("SELECT password FROM users WHERE username=?", user)
	if count != 0 {
		defer row.Close()
		var dbPass string
		row.Next()
		row.Scan(&dbPass)
		if bcrypt.CompareHashAndPassword([]byte(dbPass), []byte(pass)) == nil {
			message = "1"
		} else {
			message = "Wrong password"
		}
	}
	fmt.Fprintf(w, message)
	// }
}
func LoginpageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "template/login.html")
}
func HomepageHandler(w http.ResponseWriter, r *http.Request) {
	tmp := template.Must(template.ParseFiles("template/index.html"))
	username := r.FormValue("username")
	Username := User{Username: username}
	tmp.Execute(w, Username)
}
func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", LoginpageHandler)
	http.HandleFunc("/home", HomepageHandler)
	http.ListenAndServe(":8080", nil)
	// db, _ := sql.Open("sqlite3", "test.db")
	// hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	// db.Exec("INSERT INTO Users (username, password) VALUES (?, ?)", "admin", string(hashedPassword))

}
