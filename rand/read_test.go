package rand_test

import (
	. "github.com/IBM-Bluemix/golang-openssl-wrapper/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Read", func() {
	var seqlen int
	BeforeEach(func() {
		seqlen = 50
	})

	Context("Emulating the go native API", func() {
		var l1, l2 int
		var err error

		It("Returns a valid/random sequence of bytes", func() {
			buf := make([]byte, seqlen)
			l1, err = Read(buf)
			Expect(l1).To(Equal(len(buf)))
			Expect(err).NotTo(HaveOccurred())

			newBuf := make([]byte, seqlen)
			l2, err = Read(newBuf)
			s1 := string(buf)
			s2 := string(newBuf)

			Expect(err).NotTo(HaveOccurred())
			Expect(s1).NotTo(Equal(s2))
		})
	})
})
