package crypto_test

import (
	. "github.com/ScarletTanager/openssl/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	// "strings"
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
		var (
			// plaintext = "My Fair Lady"
			// plaintext = "My super long string to be encrypted"
			plaintext = "My super super super super duper long string to be encrypted"

			ctx                  EVP_CIPHER_CTX
			s_len, e_len         int
			encrypted, decrypted string
		)

		Context("Initializing and freeing the context", func() {
			It("should return indicating success", func() {
				ctx = EVP_CIPHER_CTX_new()
				EVP_CIPHER_CTX_init(ctx)
				Expect(EVP_CIPHER_CTX_cleanup(ctx)).To(Equal(1))
			})
		})

		Context("Encrypting a string", func() {
			var buf_encrypt []byte

			It("should initialize a new context", func() {
				ctx = EVP_CIPHER_CTX_new()
				EVP_CIPHER_CTX_init(ctx)
				Expect(ctx).NotTo(BeNil())
			})

			It("should set up the cipher context", func() {
				Expect(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))
			})

			It("should set up a buffer", func() {
				buf_encrypt = make([]byte, len(plaintext)+ctx.GetCipher().GetBlock_size())
			})

			It("should encrypt successfully", func() {
				Expect(EVP_EncryptUpdate(ctx, buf_encrypt, &s_len, plaintext, len(plaintext))).To(Equal(1))
				encrypted += string(buf_encrypt[:s_len])
			})

			It("should finalize successfully", func() {
				Expect(EVP_EncryptFinal_ex(ctx, buf_encrypt, &e_len)).To(Equal(1))
				encrypted += string(buf_encrypt[:e_len])
			})

			It("should clean up the context successfully", func() {
				Expect(EVP_CIPHER_CTX_cleanup(ctx)).To(Equal(1))
			})
		})

		Context("Decrypting a string", func() {
			var buf_decrypt []byte

			It("should initialize a new context", func() {
				ctx = EVP_CIPHER_CTX_new()
				EVP_CIPHER_CTX_init(ctx)
				Expect(ctx).NotTo(BeNil())
			})

			It("should set up the cipher context", func() {
				Expect(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))
			})

			It("should create a buffer", func() {
				buf_decrypt = make([]byte, len(encrypted))
			})

			It("should decrypt successfully", func() {
				Expect(EVP_DecryptUpdate(ctx, buf_decrypt, &s_len, encrypted, len(encrypted))).To(Equal(1))
				decrypted += string(buf_decrypt[:s_len])
			})

			It("should finalize successfully", func() {
				Expect(EVP_DecryptFinal_ex(ctx, buf_decrypt, &e_len)).To(Equal(1))
				decrypted += string(buf_decrypt[:e_len])
			})

			It("should clean up the context successfully", func() {
				Expect(EVP_CIPHER_CTX_cleanup(ctx)).To(Equal(1))
			})
		})

		It("should have matching decrypted and plaintext strings", func() {
			Expect(decrypted).To(Equal(plaintext))
		})
	})

	/*	Describe("Key Management", func() {
		Context("Using PEM", func() {

		})

	}) */
})
