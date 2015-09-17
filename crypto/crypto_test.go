package crypto_test

import (
	. "github.com/ScarletTanager/openssl/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"bytes"
//	"unsafe"
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

	
})
