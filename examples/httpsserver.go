package main

import (
	"fmt"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/ssl"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	// Get the parent directory
	d, _ := filepath.Abs(filepath.Dir(os.Args[0]))

	// Add an endpoint to the default ServeMux
	ssl.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		// Add a Server header to the response
		res.Header().Add("Server", "https://github.com/IBM-Bluemix/golang-openssl-wrapper")

		// Write the body of the response
		res.Write([]byte("Hello world!"))
	})

	fmt.Println("Starting server...")

	// Begin listening for connections
	_, e := ssl.ListenAndServeTLS(":8443", filepath.Join(d, "../ssl/tests/certs/server/server.pem"),
		filepath.Join(d, "../ssl/tests/certs/server/server.key"), nil)

	// Handle any error that was returned
	if e != nil {
		panic(e)
	}
}
