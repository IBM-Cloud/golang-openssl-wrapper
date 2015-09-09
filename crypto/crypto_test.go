package crypto_test

import (
	. "github.com/ScarletTanager/openssl/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"bytes"
)

var _ = Describe("Crypto", func() {

	Describe("Using FIPS mode", func() {

		BeforeEach(func() {
			ERR_load_crypto_strings()
			OpenSSL_add_all_algorithms()
			OPENSSL_config("")
		})

		Context("Enabling and disabling FIPS mode", func() {
			It("should return the current setting", func() {
				FIPS_mode_set(1)
				Expect(FIPS_mode()).To(Equal(1))
				FIPS_mode_set(0)
				Expect(FIPS_mode()).To(Equal(0))
			})

			It("should disallow the use of a non-approved algorithm in FIPS mode", func() {
				FIPS_mode_set(1)
				ctx := EVP_CIPHER_CTX_new()
				EVP_CIPHER_CTX_init(ctx)
				Expect(EVP_EncryptInit_ex(ctx, EVP_des_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(0))
				EVP_CIPHER_CTX_cleanup(ctx)
			})

			It("should allow the use of a non-approved algorithm after disabling FIPS mode", func() {
				FIPS_mode_set(0)
				ctx := EVP_CIPHER_CTX_new()
				EVP_CIPHER_CTX_init(ctx)
				Expect(EVP_EncryptInit_ex(ctx, EVP_des_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))
				EVP_CIPHER_CTX_cleanup(ctx)
			})

			It("should allow the use of an approved algorithm in FIPS mode", func() {
				FIPS_mode_set(1)
				ctx := EVP_CIPHER_CTX_new()
				EVP_CIPHER_CTX_init(ctx)
				Expect(EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), SwigcptrStruct_SS_engine_st(0), "thisisa256bitkeywhichhas32chars", "andwevea128bitiv")).To(Equal(1))
				EVP_CIPHER_CTX_cleanup(ctx)
			})
		})
	})

	Describe("Performing symmetric encryption", func() {
		Context("Initializing and freeing the context", func() {
			It("should return indicating success", func() {
				ctx := EVP_CIPHER_CTX_new()
				EVP_CIPHER_CTX_init(ctx)
				Expect(EVP_CIPHER_CTX_cleanup(ctx)).To(Equal(1))
			})
		})

		Context("Encrypting a string", func() {
			It("should return indicating success", func() {
				ctx := EVP_CIPHER_CTX_new()
				EVP_CIPHER_CTX_init(ctx)
				Expect(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))

				plaintext := "My Fair Lady"
				buf_encrypt := make([]byte, len(plaintext) + ctx.GetCipher().GetBlock_size())
				c_len := []int{0}

				Expect(EVP_EncryptUpdate(ctx, buf_encrypt, c_len, plaintext, len(plaintext))).To(Equal(1))

				buf_final := make([]byte, len(plaintext) + ctx.GetCipher().GetBlock_size())
				c_fin := []int{0}
				Expect(EVP_EncryptFinal_ex(ctx, buf_final, c_fin)).To(Equal(1))

				EVP_CIPHER_CTX_cleanup(ctx)
			})
		})

		Context("Decrypting a string", func() {
			ctx := EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctx)
			EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")

			var b bytes.Buffer
			plaintext := "My Fair Lady"
			buf_encrypt := make([]byte, len(plaintext) + ctx.GetCipher().GetBlock_size())
			c_len := []int{0}

			EVP_EncryptUpdate(ctx, buf_encrypt, c_len, plaintext, len(plaintext))
			b.Write(buf_encrypt)

			buf_final := make([]byte, len(plaintext) + ctx.GetCipher().GetBlock_size())
			c_fin := []int{0}
			EVP_EncryptFinal_ex(ctx, buf_final, c_fin)
			b.Write(buf_final)

			EVP_CIPHER_CTX_cleanup(ctx)

			dtx := EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(dtx)

			It("should initialize successfully", func() {
				Expect(EVP_DecryptInit_ex(dtx, EVP_aes_256_cfb(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))
			})

/*			encrypted := b.String()
			buf_decrypt := make([]byte, len(encrypted) + ctx.GetCipher().GetBlock_size())
			d_len := []int{0}

			It("should decrypt successfully", func() {
				Expect(EVP_DecryptUpdate(ctx, buf_decrypt, d_len, encrypted, len(encrypted))).To(Equal(1))
			}) */

			EVP_CIPHER_CTX_cleanup(dtx)
		})
	})

/*	Describe("Key Management", func() {
		Context("Using PEM", func() {

		})

	}) */

	Describe("Basic I/O", func() {
		Context("Making a connection", func() {
			It("Connects successfully", func() {
				dest := "www.google.com:http"
				bio := BIO_new_connect(dest)
				Expect(bio).NotTo(BeNil())
				Expect(BIO_do_connect(bio)).To(BeEquivalentTo(1))
				Expect(BIO_free(bio)).To(Equal(1))
			})
		})

		Context("File I/O", func() {
			mode := "w+"
			filename := "biotest.out"
			text := "To Kill A Mockingbird"

			fbio := BIO_new_file(filename, mode)

			It("Writes to the file", func() {
				Expect(fbio).NotTo(BeNil())
				Expect(BIO_puts(fbio, text)).To(BeNumerically(">=", 1))
				Expect(BIO_flush(fbio)).To(BeEquivalentTo(1))
				/* For file BIOs, BIO_seek() returns 0 on success */
				Expect(BIO_seek(fbio, 0)).To(BeEquivalentTo(0))
			})

/*			It("Reads from the file", func() {
				rbuf := make([]byte, len(text) + 1)
				Expect(len(text)).To(Equal(21))
				Expect(len(rbuf)).To(Equal(22))
				l := BIO_gets(fbio, rbuf, len(text) +1)
				Expect(l).To(BeNumerically(">=", len(text)))
				s := string(rbuf[:l])
				Expect(s).To(Equal(text))
			}) */
		})
	})
})
