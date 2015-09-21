package ssl_test

import (
	. "github.com/ScarletTanager/openssl/ssl"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"time"
)

var _ = Describe("Httpsclient", func() {

	var t http.Transport
	var h HttpsConn
	BeforeEach(func() {
		t = NewHttpsTransport()
		Expect(t).NotTo(BeNil())
	})

	Context("Establishing a connection", func() {
		It("Should error for an invalid network type", func() {
			conn, err := t.Dial("bogus", "www.google.com:443")
			Expect(conn).To(BeNil())
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Performing socket I/O", func() {
		BeforeEach(func() {
			conn, err := t.Dial("tcp", "somevalidsite")
			Expect(err).NotTo(HaveOccurred())
			h = conn.(HttpsConn)
		})

		It("Should read from the connection", func() {
			b := make([]byte, 50)
			Expect(h.Read(b)).To(BeNumerically(">", 0))
		})

		It("Should write to the connection", func() {
			b := []byte("String to turn into bytes")
			Expect(h.Write(b)).To(BeNumerically(">=", len(b)))
		})

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
			bogus := now.Add(time.Duration(10) * time.Minute)
			Expect(h.SetDeadLine(bogus)).NotTo(Succeed())
			Expect(h.SetReadDeadLine(bogus)).NotTo(Succeed())
			Expect(h.SetWriteDeadLine(bogus)).NotTo(Succeed())
		})

		// TODO: Specs for checking that deadlines, having been set, are observed
	})
})
