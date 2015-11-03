package rand_test

import (
	. "github.com/IBM-Bluemix/golang-openssl-wrapper/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Rand", func() {

	var seqlen int
	BeforeEach(func() {
		seqlen = 50
	})

	Context("Using /dev/urandom for PRNG entropy", func() {
		It("Returns a valid/random sequence of bytes", func() {
			seqlen := 50
			buf := make([]byte, seqlen)
			Expect(RAND_bytes(buf, seqlen)).To(Equal(1))
			Expect(len(string(buf))).To(Equal(50))
		})
	})
})
