package digest_test

import (
	. "github.com/IBM-Bluemix/golang-openssl-wrapper/digest"

	"bytes"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/rand"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"strings"
)

var _ = Describe("Hash", func() {

	Context("Emulating the golang native crypto/sha256 API", func() {
		var (
			ret        int
			err        error
			data, key1 []byte
			seqlen     int
			hasher1    *Digest
		)

		BeforeEach(func() {
			seqlen = 50
			data = make([]byte, seqlen)
			Expect(rand.RAND_bytes(data, seqlen)).To(Equal(1))

			hasher1 = NewSHA256()
			Expect(hasher1).NotTo(BeNil())
			ret, err = hasher1.Write(data)
			Expect(ret).To(Equal(len(data)))
			Expect(err).NotTo(HaveOccurred())
			key1 = hasher1.Sum(nil)

			Expect(len(key1)).To(BeNumerically(">", 0))
		})

		It("Returns the correct digest length", func() {
			s := EVP_MD_size(EVP_sha256())
			Expect(s).To(BeNumerically(">", 0))
			Expect(hasher1.Size()).To(Equal(s))
		})

		It("Returns the correct block size", func() {
			s := EVP_MD_block_size(EVP_sha256())
			Expect(s).To(BeNumerically(">", 0))
			Expect(hasher1.BlockSize()).To(Equal(s))
		})

		It("Produces identical hash values from the same binary data", func() {
			hasher2 := NewSHA256()
			Expect(hasher2).NotTo(BeNil())
			ret, err = hasher2.Write(data)
			Expect(ret).To(Equal(len(data)))
			Expect(err).NotTo(HaveOccurred())
			key2 := hasher2.Sum(nil)

			Expect(len(key2)).To(BeNumerically(">", 0))

			Expect(bytes.Equal(key1, key2)).To(BeTrue())
		})

		It("Produces different hash values from different inputs", func() {
			data2 := make([]byte, seqlen)
			Expect(rand.RAND_bytes(data2, seqlen)).To(Equal(1))

			hasher2 := NewSHA256()
			Expect(hasher2).NotTo(BeNil())
			ret, err = hasher2.Write(data2)
			Expect(ret).To(Equal(len(data2)))
			Expect(err).NotTo(HaveOccurred())
			key2 := hasher2.Sum(nil)

			Expect(len(key2)).To(BeNumerically(">", 0))

			Expect(bytes.Equal(key1, key2)).To(BeFalse())
		})

		It("Appends to an existing hash key", func() {
			newKey := hasher1.Sum(key1)
			Expect(strings.HasPrefix(string(newKey), string(key1))).To(BeTrue())
		})
	})
})
