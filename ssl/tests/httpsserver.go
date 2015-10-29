package main

import (
	"fmt"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/ssl"
	"github.com/gorilla/mux"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	setup()

	d, _ := filepath.Abs(filepath.Dir(os.Args[0]))

	fmt.Println("Server listening on port 8443")
	_, e := ssl.ListenAndServeTLS(":8443", filepath.Join(d, "certs/server/server.pem"),
		filepath.Join(d, "certs/server/server.key"), nil)

	if e != nil {
		panic(e)
	}
}

func setup() {
	ssl.HandleFunc("/aloha", func(res http.ResponseWriter, req *http.Request) {
		headers(res)
		aloha(res)
	})

	ssl.HandleFunc("/server", func(res http.ResponseWriter, req *http.Request) {
		headers(res)
		res.Write([]byte(""))
	})

	r := mux.NewRouter()
	r.HandleFunc("/mux", func(res http.ResponseWriter, req *http.Request) {
		headers(res)
		res.Write([]byte("Using gorilla/mux"))
	})
	ssl.Handle("/mux", r)
}

func aloha(res http.ResponseWriter) {
	res.Write([]byte("ALOHA!!"))
}

func headers(res http.ResponseWriter) {
	res.Header().Add("Server", "https://github.com/IBM-Bluemix/golang-openssl-wrapper")
}
