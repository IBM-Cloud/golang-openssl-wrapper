package rand_test

import (
	. "github.com/ScarletTanager/openssl/rand"

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
