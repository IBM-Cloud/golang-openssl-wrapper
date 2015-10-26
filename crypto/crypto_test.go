package crypto_test

import (
	. "github.com/ScarletTanager/openssl/crypto"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	// "strings"
	//	"unsafe"
	"github.com/ScarletTanager/openssl/rand"
)

var _ = Describe("Crypto", func() {

	var (
		// plaintext = "My Fair Lady"
		// plaintext = "My super long string to be encrypted"
		plaintext = "My super super super super duper long string to be encrypted"

		sLen, eLen             int
		encrypted, decrypted   string
		bufEncrypt, bufDecrypt []byte
		ctxEncrypt, ctxDecrypt EVP_CIPHER_CTX
	)

	BeforeEach(func() {
		/*
		 * Setup OpenSSL
		 */
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
			ctxEncrypt = EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctxEncrypt)
			Expect(EVP_EncryptInit_ex(ctxEncrypt, EVP_des_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(0))
			EVP_CIPHER_CTX_cleanup(ctxEncrypt)
		})

		It("should allow the use of a non-approved algorithm after disabling FIPS mode", func() {
			FIPS_mode_set(0)
			ctxEncrypt = EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctxEncrypt)
			Expect(EVP_EncryptInit_ex(ctxEncrypt, EVP_des_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))
			EVP_CIPHER_CTX_cleanup(ctxEncrypt)
		})

		It("should allow the use of an approved algorithm in FIPS mode", func() {
			FIPS_mode_set(1)
			EVP_CIPHER_CTX_init(ctxEncrypt)
			Expect(EVP_EncryptInit_ex(ctxEncrypt, EVP_aes_256_cfb(), SwigcptrStruct_SS_engine_st(0), "thisisa256bitkeywhichhas32chars", "andwevea128bitiv")).To(Equal(1))
			EVP_CIPHER_CTX_cleanup(ctxEncrypt)
		})
	}) // END Context

	Context("Initializing and freeing the context", func() {
		It("should return indicating success", func() {
			ctxEncrypt = EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctxEncrypt)
			Expect(EVP_CIPHER_CTX_cleanup(ctxEncrypt)).To(Equal(1))
		})
	})

	Context("Encrypting in CBC mode with FIPS mode disabled", func() {
		BeforeEach(func() {
			/* Be sure FIPS mode is disabled */
			FIPS_mode_set(0)
			Expect(FIPS_mode()).To(Equal(0))

			ctxEncrypt = EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctxEncrypt)
			Expect(ctxEncrypt).NotTo(BeNil())
		})

		It("should encrypt successfully", func() {
			Expect(EVP_EncryptInit_ex(ctxEncrypt, EVP_aes_256_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))
			bufEncrypt = make([]byte, len(plaintext)+ctxEncrypt.GetCipher().GetBlock_size())
			Expect(EVP_EncryptUpdate(ctxEncrypt, bufEncrypt, &sLen, plaintext, len(plaintext))).To(Equal(1))
			encrypted = string(bufEncrypt[:sLen])
			Expect(EVP_EncryptFinal_ex(ctxEncrypt, bufEncrypt, &eLen)).To(Equal(1))
			encrypted += string(bufEncrypt[:eLen])
		})

		AfterEach(func() {
			Expect(EVP_CIPHER_CTX_cleanup(ctxEncrypt)).To(Equal(1))
		})
	})

	Context("Decrypting a string", func() {
		BeforeEach(func() {
			FIPS_mode_set(0)
			Expect(FIPS_mode()).To(Equal(0))

			/* Setup an encryption context and create our encrypted string */
			ctxEncrypt = EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctxEncrypt)
			Expect(ctxEncrypt).NotTo(BeNil())

			Expect(EVP_EncryptInit_ex(ctxEncrypt, EVP_aes_256_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))

			bufEncrypt = make([]byte, len(plaintext)+ctxEncrypt.GetCipher().GetBlock_size())

			Expect(EVP_EncryptUpdate(ctxEncrypt, bufEncrypt, &sLen, plaintext, len(plaintext))).To(Equal(1))
			encrypted = string(bufEncrypt[:sLen])

			Expect(EVP_EncryptFinal_ex(ctxEncrypt, bufEncrypt, &eLen)).To(Equal(1))
			encrypted += string(bufEncrypt[:eLen])

			Expect(EVP_CIPHER_CTX_cleanup(ctxEncrypt)).To(Equal(1))
		})

		It("should decrypt successfully", func() {
			ctxDecrypt = EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctxDecrypt)
			Expect(ctxDecrypt).NotTo(BeNil())

			Expect(EVP_DecryptInit_ex(ctxDecrypt, EVP_aes_256_cbc(), SwigcptrStruct_SS_engine_st(0), "somekey", "someiv")).To(Equal(1))

			bufDecrypt = make([]byte, len(encrypted))
			Expect(EVP_DecryptUpdate(ctxDecrypt, bufDecrypt, &sLen, encrypted, len(encrypted))).To(Equal(1))

			decrypted = string(bufDecrypt[:sLen])
			// bufFinal := make([]byte, len(encrypted))
			Expect(EVP_DecryptFinal_ex(ctxDecrypt, bufDecrypt, &eLen)).To(Equal(1))

			decrypted += string(bufDecrypt[:eLen])
			Expect(decrypted).To(Equal(plaintext))
		})

	})

	Context("Using AEAD (authenticated encryption)", func() {
		var (
			key, iv, aad        string
			ivLen, aLen, tagLen int
			tag                 []byte
		)

		BeforeEach(func() {
			/* Create contexts for encryption and decryption */
			ivLen = 12 // Standard length for AEAD
			ctxEncrypt = EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctxEncrypt)
			ctxDecrypt = EVP_CIPHER_CTX_new()
			EVP_CIPHER_CTX_init(ctxDecrypt)

			Expect(ctxEncrypt).NotTo(BeNil())
			Expect(ctxDecrypt).NotTo(BeNil())
			key = "somekey"

			/* Setup a random IV */
			buf := make([]byte, ivLen)
			l, err := rand.Read(buf)
			Expect(err).NotTo(HaveOccurred())
			Expect(l).To(Equal(len(buf)))
			iv = string(buf)

			/* Get our aad - in a real world use, this could be almost anything, e.g. a host:ip tuple */
			aad = "additionalAuthenticationData"

			tagLen = 16
			tag = make([]byte, tagLen)

			encrypted = ""
			decrypted = ""
		})

		It("Encrypts and decrypts a string using a standard 12 byte IV", func() {
			Expect(EVP_EncryptInit_ex(ctxEncrypt, EVP_aes_256_gcm(), SwigcptrStruct_SS_engine_st(0), key, iv)).To(Equal(1))

			/* Provide the aad data */
			Expect(EVP_EncryptUpdate(ctxEncrypt, nil, &aLen, aad, len(aad))).To(Equal(1))

			/*
			 * Encrypt
			 */
			bufEncrypt = make([]byte, len(plaintext)+ctxEncrypt.GetCipher().GetBlock_size())
			Expect(EVP_EncryptUpdate(ctxEncrypt, bufEncrypt, &sLen, plaintext, len(plaintext))).To(Equal(1))
			encrypted += string(bufEncrypt[:sLen])
			Expect(EVP_EncryptFinal_ex(ctxEncrypt, bufEncrypt, &eLen)).To(Equal(1))
			encrypted += string(bufEncrypt[:eLen])

			/* Get the tag - *must* be done after calling EVP_EncryptFinal_ex() */
			// Expect(EVP_CIPHER_CTX_ctrl(ctxEncrypt, EVP_CTRL_GCM_GET_TAG, tagLen, tag)).To(Equal(1))
			Expect(GET_TAG_GCM(ctxEncrypt, EVP_CTRL_GCM_GET_TAG, tagLen, tag)).To(Equal(1))
			Expect(len(tag)).To(Equal(tagLen))

			Expect(EVP_CIPHER_CTX_cleanup(ctxEncrypt)).To(Equal(1))

			/*
			 * Decrypt
			 */
			/* Since we're using the default IV length of 12 bytes, we don't need to set it */
			Expect(EVP_DecryptInit_ex(ctxDecrypt, EVP_aes_256_gcm(), SwigcptrStruct_SS_engine_st(0), key, iv)).To(Equal(1))

			/* Set the tag to what we expect */
			tagString := string(tag)
			// Expect(EVP_CIPHER_CTX_ctrl(ctxDecrypt, EVP_CTRL_GCM_SET_TAG, tagLen, tag)).To(Equal(1))
			Expect(SET_TAG_GCM(ctxDecrypt, EVP_CTRL_GCM_SET_TAG, tagLen, tagString)).To(Equal(1))

			/* Provide the aad data */
			Expect(EVP_DecryptUpdate(ctxDecrypt, nil, &aLen, aad, len(aad))).To(Equal(1))

			/* Decrypt - tag must be set before we call EVP_DecryptUpdate() */
			bufDecrypt = make([]byte, len(encrypted))
			Expect(EVP_DecryptUpdate(ctxDecrypt, bufDecrypt, &sLen, encrypted, len(encrypted))).To(Equal(1))
			decrypted += string(bufDecrypt[:sLen])

			Expect(EVP_DecryptFinal_ex(ctxDecrypt, bufDecrypt, &eLen)).To(Equal(1))
			decrypted += string(bufDecrypt[:eLen])

			Expect(decrypted).To(Equal(plaintext))
			Expect(EVP_CIPHER_CTX_cleanup(ctxDecrypt)).To(Equal(1))
		})
	})

})
