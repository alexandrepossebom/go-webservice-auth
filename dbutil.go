package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

func getUser(name, password string) (error, bool) {
	db, err := sql.Open("sqlite3", "./users.db")
	defer db.Close()

	if err != nil {
		log.Fatal(err)
		return err, false
	}

	stmt, err := db.Prepare("select isAdmin from users where name = ? and password = ? limit 1")
	defer stmt.Close()
	if err != nil {
		log.Fatal(err)
		return err, false
	}

	var admin bool
	err = stmt.QueryRow(name, password).Scan(&admin)
	return err, admin
}
