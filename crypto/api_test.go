package crypto_test

import (
	. "github.com/IBM-Bluemix/golang-openssl-wrapper/crypto"

	// "fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Api", func() {
	var (
		plaintext = "some plaintext"
	)

	Context("Symmetric encryption with API", func() {
		BeforeEach(func() {
			FIPS_mode_set(0)
		})

		It("should encrypt and decrypt successfully", func() {
			cipher := NewAESCBC("some key")
			Expect(cipher).NotTo(BeNil())

			enc := NewEncrypter(cipher, "some iv")
			Expect(enc).NotTo(BeNil())

			buf := make([]byte, len(plaintext)+enc.BlockSize)
			copy(buf, plaintext)
			Expect(buf[:len(plaintext)]).To(Equal([]byte(plaintext)))

			re, e := enc.Encrypt(buf, []byte(plaintext))
			Expect(e).NotTo(HaveOccurred())

			dec := NewDecrypter(cipher, "some iv")
			Expect(dec).NotTo(BeNil())

			rd, e := dec.Decrypt(buf, buf[:re])
			Expect(e).NotTo(HaveOccurred())
			Expect(rd).To(Equal(len(plaintext)))

			Expect(buf[:rd]).To(Equal([]byte(plaintext)))
		})

		It("should disallow the use of a non-approved algorithm in FIPS mode", func() {
			FIPS_mode_set(1)

			cipher := NewDESCBC("some key")
			Expect(cipher).NotTo(BeNil())

			enc := NewEncrypter(cipher, "some iv")
			Expect(enc).NotTo(BeNil())

			buf := make([]byte, 20)
			_, e := enc.Encrypt(buf, buf)
			Expect(e).To(HaveOccurred())
		})

		It("should allow the use of an approved algorithm in FIPS mode", func() {
			FIPS_mode_set(1)

			cipher := NewAESCBC("some key")
			Expect(cipher).NotTo(BeNil())

			enc := NewEncrypter(cipher, "some iv")
			Expect(enc).NotTo(BeNil())

			buf := make([]byte, 20)
			_, e := enc.Encrypt(buf, buf)
			Expect(e).NotTo(HaveOccurred())
		})

		It("should allow the IV to be changed", func() {
			cipher := NewAESCBC("some key")
			Expect(cipher).NotTo(BeNil())

			enc := NewEncrypter(cipher, "some iv")
			Expect(enc).NotTo(BeNil())

			eb1 := make([]byte, len(plaintext)+enc.BlockSize)
			_, e := enc.Encrypt(eb1, []byte(plaintext))
			Expect(e).NotTo(HaveOccurred())

			enc = enc.SetIV("some other iv")

			eb2 := make([]byte, len(plaintext)+enc.BlockSize)
			_, e = enc.Encrypt(eb2, []byte(plaintext))
			Expect(e).NotTo(HaveOccurred())

			Expect(eb1).NotTo(Equal(eb2))
		})

		It("should be able to reuse an existing encrypter as a decrypter", func() {
			cipher := NewAESCBC("some key")
			Expect(cipher).NotTo(BeNil())

			enc := NewEncrypter(cipher, "some iv")
			Expect(enc).NotTo(BeNil())

			buf := make([]byte, len(plaintext)+enc.BlockSize)

			re, e := enc.Encrypt(buf, []byte(plaintext))
			Expect(e).NotTo(HaveOccurred())

			dec := Decrypter(enc)

			rd, e := dec.Decrypt(buf, buf[:re])
			Expect(e).NotTo(HaveOccurred())

			Expect(buf[:rd]).To(Equal([]byte(plaintext)))

		})
	})
})
