package ssl_test

import (
	. "github.com/ScarletTanager/openssl/ssl"

	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"
	"net/http"
	// "net/url"
	"strings"
	"time"
)

var _ = Describe("Httpsclient", func() {

	var t *http.Transport
	var h HttpsConn
	var host, resource string
	var respLen int
	var port, ua, dest, requestContent string
	// var server *httptest.Server

	BeforeEach(func() {
		host = "www.random.org"
		respLen = 8
		resource = fmt.Sprintf("/strings/?num=1&len=%d&digits=on&upperalpha=on&loweralpha=on&unique=on&format=plain&rnd=new", respLen)
	})

	// AfterEach(func() {
	// 	server.Close()
	// })

	Context("Using the golang http.Client", func() {
		It("Should fetch a resource successfully", func() {
			client := NewHttpsClient()
			urlPath := "https://" + host + resource
			response, err := client.Get(urlPath)
			Expect(err).To(BeNil())

			defer response.Body.Close()
			body, _ := ioutil.ReadAll(response.Body)
			bstring := strings.Trim(string(body), "\n")
			Expect(len(bstring)).To(Equal(respLen))
		})
	})

	Context("Working directly with the underlying Transport", func() {
		BeforeEach(func() {
			port = "443"
			ua = "https://github.com/ScarletTanager/openssl"
			/* Fetch a single 8 character string in plaintext format */
			requestContent = strings.Join([]string{
				fmt.Sprintf("GET %s HTTP/1.1", resource),
				fmt.Sprintf("User-Agent: %s", ua),
				fmt.Sprintf("Host: %s", host),
				"Accept: */*",
				"\r\n",
			}, "\r\n")
			dest = host + ":" + port
			/*
			 * Setup our mock HTTPS server
			 */
			// server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 	fmt.Fprintln(w, "TESTING")
			// }))
			// Expect(server).NotTo(BeNil())

			// t = NewHttpsTransport(func(req *http.Request) (*url.URL, error) {
			// 	return url.Parse(server.URL)
			// })
			t = NewHttpsTransport(nil)
			Expect(t).NotTo(BeNil())
			conn, err := t.Dial("tcp", dest)
			Expect(err).NotTo(HaveOccurred())
			h = conn.(HttpsConn)
		})

		It("Should error for an invalid network type", func() {
			conn, err := t.Dial("bogus", "www.google.com:443")
			Expect(conn).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		Context("Performing socket I/O", func() {
			AfterEach(func() {
				h.Close()
			})

			It("Should write to the connection and read the response", func() {
				wb := []byte(requestContent)
				Expect(h.Write(wb)).To(BeNumerically(">=", len(wb)))
				rb := make([]byte, 50)
				Expect(h.Read(rb)).To(BeNumerically(">", 0))
			})
		})

		Context("Connection management", func() {
			It("Should not allow closing of an already closed connection", func() {
				h.Close()
				Expect(h.Close()).NotTo(Succeed())
			})

		})

		Context("Setting deadlines", func() {
			var now time.Time
			BeforeEach(func() {
				now = time.Now()
			})

			It("Should not allow setting a deadline equal or or before the current time", func() {
				bogus := now.Add(time.Duration(10) * time.Second * (-1))
				Expect(h.SetDeadLine(bogus)).NotTo(Succeed())
				Expect(h.SetReadDeadLine(bogus)).NotTo(Succeed())
				Expect(h.SetWriteDeadLine(bogus)).NotTo(Succeed())
			})

			It("Should not allow setting a deadline more than ten (10) minutes in the future", func() {
				bogus := now.Add(time.Duration(11) * time.Minute)
				Expect(h.SetDeadLine(bogus)).NotTo(Succeed())
				Expect(h.SetReadDeadLine(bogus)).NotTo(Succeed())
				Expect(h.SetWriteDeadLine(bogus)).NotTo(Succeed())
			})

			// TODO: Specs for checking that deadlines, having been set, are observed
		})
	})
})
