package main

import (
	"fmt"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/crypto"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/rand"
)

func main() {
	var (
		plaintext = "My super super super super duper long string to be encrypted"
		ivLen     = 12

		sLen, eLen               int
		encrypted, decrypted, iv string
		bufEncrypt, bufDecrypt   []byte
		ctxEncrypt, ctxDecrypt   crypto.EVP_CIPHER_CTX
	)

	// Setup error strings
	crypto.ERR_load_crypto_strings()

	// Add all OpenSSL algorithms
	crypto.OpenSSL_add_all_algorithms()

	// Load an OpenSSL config
	crypto.OPENSSL_config("")

	// Enable FIPS mode
	crypto.FIPS_mode_set(1)

	// Create new EVP_CIPHER_CTX instances
	ctxEncrypt, ctxDecrypt = crypto.EVP_CIPHER_CTX_new(), crypto.EVP_CIPHER_CTX_new()

	// Panic if either EVP_CIPHER_CTX fails to create
	if ctxEncrypt == nil {
		panic("ctxEncrypt is nil")
	}
	if ctxDecrypt == nil {
		panic("ctxDecrypt is nil")
	}

	// Initialize the EVP_CIPHER_CTX instances
	crypto.EVP_CIPHER_CTX_init(ctxEncrypt)
	crypto.EVP_CIPHER_CTX_init(ctxDecrypt)

	// Create random IV for nondeterministic encryption
	buf := make([]byte, ivLen)
	_, e := rand.Read(buf)
	if e != nil {
		panic(e)
	}
	iv = string(buf)

	// Pass the IV into the encrypted string to be used when decoding
	encrypted = iv

	// Print plaintext string
	fmt.Printf("plaintext: %s\n", plaintext)

	/*
		Encrypting a string
	*/
	// Initialize the ctxEncrypt context for encryption
	crypto.EVP_EncryptInit_ex(ctxEncrypt, crypto.EVP_aes_256_cbc(), crypto.SwigcptrStruct_SS_engine_st(0), "somekey", iv)

	// Make a buffer with enough size for the plaintext plus one block
	bufEncrypt = make([]byte, len(plaintext)+ctxEncrypt.GetCipher().GetBlock_size())

	// Update the cipher with some content
	crypto.EVP_EncryptUpdate(ctxEncrypt, bufEncrypt, &sLen, plaintext, len(plaintext))

	// Append encrypted data to encrypted string
	encrypted += string(bufEncrypt[:sLen])

	// Finalize the cipher to flush any remaining data
	crypto.EVP_EncryptFinal_ex(ctxEncrypt, bufEncrypt, &eLen)

	// Append any remaining data to the encrypted string
	encrypted += string(bufEncrypt[:eLen])

	// Clean up the EVP_CIPHER_CTX
	crypto.EVP_CIPHER_CTX_cleanup(ctxEncrypt)

	/*
		Decrypting a string
	*/
	// Grab the IV from the encrypted string
	iv = string([]byte(encrypted)[:ivLen])

	// Slice the encrypted string to begin after the iv
	encrypted = encrypted[ivLen:]

	// Initialize the ctxDecrypt context for decryption
	crypto.EVP_DecryptInit_ex(ctxDecrypt, crypto.EVP_aes_256_cbc(), crypto.SwigcptrStruct_SS_engine_st(0), "somekey", iv)

	// Make a buffer the exact size of the encrypted text
	bufDecrypt = make([]byte, len(encrypted))

	// Update the cipher with the encrypted string
	crypto.EVP_DecryptUpdate(ctxDecrypt, bufDecrypt, &sLen, encrypted, len(encrypted))

	// Append decrypted data to decrypted string
	decrypted = string(bufDecrypt[:sLen])

	// Finalize the cipher to flush any remaining data
	crypto.EVP_DecryptFinal_ex(ctxDecrypt, bufDecrypt, &eLen)

	// Append any remaining data to decrypted string
	decrypted += string(bufDecrypt[:eLen])

	// Print decoded string
	fmt.Printf("decrypted: %s\n", decrypted)

	// Clean up the EVP_CIPHER_CTX
	crypto.EVP_CIPHER_CTX_cleanup(ctxDecrypt)
}
