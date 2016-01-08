package ssl_test

import (
	. "github.com/IBM-Bluemix/golang-openssl-wrapper/ssl"

	"net/http"
	"os"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var c *exec.Cmd
var _ = BeforeSuite(compileAndStartServer)
var _ = AfterSuite(cleanup)

var _ = Describe("Httpsserver", func() {
	It("Should get a valid response from the /aloha endpoint", func() {
		client := NewHTTPSClient()
		url := "https://localhost:8443/aloha"
		res, e := client.Get(url)
		Expect(e).To(BeNil())
		Expect(res).NotTo(BeNil())

		body := make([]byte, 200)
		i, e := res.Body.Read(body)
		Expect(e).To(BeNil())
		Expect(i).To(BeNumerically(">", 0))
		Expect(string(body[:i])).To(Equal("ALOHA!!"))
		Expect(res.Body.Close()).To(BeNil())
	})

	It("Should get a valid response from the /server endpoint", func() {
		client := NewHTTPSClient()
		url := "https://localhost:8443/server"
		res, e := client.Get(url)
		Expect(e).To(BeNil())
		Expect(res).NotTo(BeNil())

		Expect(res.Header.Get("Server")).To(Equal("https://github.com/IBM-Bluemix/golang-openssl-wrapper"))
		Expect(res.Body.Close()).To(BeNil())
	})

	It("Should get a valid response from the /mux endpoint", func() {
		client := NewHTTPSClient()
		url := "https://localhost:8443/mux"
		res, e := client.Get(url)
		Expect(e).To(BeNil())
		Expect(res).NotTo(BeNil())

		body := make([]byte, 200)
		i, e := res.Body.Read(body)
		Expect(e).To(BeNil())
		Expect(i).To(BeNumerically(">", 0))
		Expect(string(body[:i])).To(Equal("Using gorilla/mux"))
		Expect(res.Body.Close()).To(BeNil())
	})

	It("Should not try handling any non-HTTPS requests", func() {
		_, e := http.Get("http://localhost:8443/aloha")
		Expect(e).To(HaveOccurred())
	})
})

func cleanup() {
	c.Process.Kill()
}

func compileAndStartServer() {
	check := func(e error) {
		if e != nil {
			panic(e)
		}
	}

	check(os.Chdir("tests"))

	// Compile HTTPSServer
	c = exec.Command("go", "build", "httpsserver.go")
	check(c.Start())
	check(c.Wait())

	// Run HTTPSServer
	c = exec.Command("./httpsserver")
	check(c.Start())

	time.Sleep(2 * time.Second)
}
