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

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Add an endpoint to the ServeMux
	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		// Add a Server header to the response
		res.Header().Add("Server", "https://github.com/IBM-Bluemix/golang-openssl-wrapper")

		// Write the body of the response
		res.Write([]byte("Hello world!"))
	})

	// Create a new Server with the custom ServeMux
	server := &ssl.Server{
		Addr: ":8443",

		// Set the Handler to our ServeMux
		Handler: mux,
	}

	fmt.Println("Starting server...")

	// Begin listening for connections
	e := server.ListenAndServeTLS(filepath.Join(d, "../ssl/tests/certs/server/server.pem"),
		filepath.Join(d, "../ssl/tests/certs/server/server.key"))

	// Handle any error that was returned
	if e != nil {
		panic(e)
	}
}
