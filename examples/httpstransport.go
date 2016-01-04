package main

import (
	"fmt"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/ssl"
	"io/ioutil"
	"net/http"
	"strings"
)

func main() {
	// Create a new HTTPS client
	client := http.Client{
		// Use our transport for FIPS compliant OpenSSL
		Transport: ssl.NewHTTPSTransport(nil),
	}

	// Call HTTP GET on the client
	response, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		panic(err)
	}

	// Defer closing the response body so it isn't forgotten.
	defer response.Body.Close()

	// Read the entire body
	body, _ := ioutil.ReadAll(response.Body)

	// Convert body to string and trim newlines
	bstring := strings.Trim(string(body), "\n")

	// Print response
	fmt.Printf("https://httpbin.org/ip response:\n%s\n", bstring)
}
