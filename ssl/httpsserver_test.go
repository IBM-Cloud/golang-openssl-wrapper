package ssl_test

import (
	. "github.com/ScarletTanager/openssl/ssl"

	"os"
	"os/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Httpsserver", func() {
	compileAndStartServer()

	It("Should get a valid response from the /aloha endpoint", func() {
		client := NewHTTPSClient()
		url := "https://localhost:8443/aloha"
		res, e := client.Get(url)
		Expect(e).To(BeNil())
		Expect(res).NotTo(BeNil())
	})

	It("Should get a valid response from the /server endpoint", func() {
		client := NewHTTPSClient()
		url := "https://localhost:8443/server"
		res, e := client.Get(url)
		Expect(e).To(BeNil())
		Expect(res).NotTo(BeNil())
	})

	It("Should get a valid response from the /mux endpoint", func() {
		client := NewHTTPSClient()
		url := "https://localhost:8443/mux"
		res, e := client.Get(url)
		Expect(e).To(BeNil())
		Expect(res).NotTo(BeNil())
	})
})

func compileAndStartServer() {
	var c *exec.Cmd

	check := func(e error) {
		if e != nil {
			panic(e)
		}
	}

	check(os.Chdir("../tests/ssl"))

	// Compile HTTPSServer
	c = exec.Command("go", "build", "httpsserver.go")
	check(c.Start())
	check(c.Wait())

	// Run HTTPSServer
	c = exec.Command("./httpsserver")
	check(c.Start())
}
