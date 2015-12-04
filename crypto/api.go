package crypto

import (
	"fmt"
)

type Cipher struct {
	CipherMethod

	BlockSize int

	ctx EVP_CIPHER_CTX
	iv  string

	init   func(EVP_CIPHER_CTX, EVP_CIPHER, Struct_SS_engine_st, string, string) int
	update func(EVP_CIPHER_CTX, []byte, *int, string, int) int
	final  func(EVP_CIPHER_CTX, []byte, *int) int
}

type CipherMethod interface {
	Key() string
	Method() EVP_CIPHER
}

func NewCipher(method CipherMethod, iv string) Cipher {
	ERR_load_crypto_strings()
	OpenSSL_add_all_algorithms()
	OPENSSL_config("")

	ctx := EVP_CIPHER_CTX_new()
	EVP_CIPHER_CTX_init(ctx)

	c := Cipher{
		CipherMethod: method,
		BlockSize:    EVP_CIPHER_block_size(method.Method()),
		ctx:          ctx,
		iv:           iv,
	}
	return c
}

func (c Cipher) Init() error {
	if c.init(c.ctx, c.Method(), SwigcptrStruct_SS_engine_st(0), c.Key(), c.iv) != 1 {
		return fmt.Errorf("%s", ERR_error_string(ERR_get_error(), nil))
	}
	return nil
}

func (c Cipher) Bytes(dst, src []byte) (int, error) {
	var pos, end int

	out := make([]byte, len(src)+c.BlockSize)
	buf := make([]byte, len(src)+c.BlockSize)

	if c.update(c.ctx, buf, &pos, string(src), len(src)) != 1 {
		return pos, fmt.Errorf("%s", ERR_error_string(ERR_get_error(), nil))
	}
	copy(out, buf[:pos])

	res := c.final(c.ctx, buf, &end) == 1
	read := pos + end

	if !res {
		return read, fmt.Errorf("%s", ERR_error_string(ERR_get_error(), nil))
	}
	copy(out[pos:read], buf[:end])

	EVP_CIPHER_CTX_cleanup(c.ctx)

	return copy(dst, out[:read]), nil
}

func (c Cipher) SetIV(iv string) Cipher {
	c.iv = iv
	return c
}

type Encrypter Cipher
type Decrypter Cipher

func NewDecrypter(method CipherMethod, iv string) Decrypter {
	c := NewCipher(method, iv)
	return Decrypter(c)
}

func (d Decrypter) Decrypt(dst, src []byte) (int, error) {
	c := Cipher(d)
	c.init = EVP_DecryptInit_ex
	c.update = EVP_DecryptUpdate
	c.final = EVP_DecryptFinal_ex
	if e := c.Init(); e != nil {
		return 0, e
	}
	return c.Bytes(dst, src)
}

func (d Decrypter) SetIV(iv string) Decrypter {
	d = Decrypter(Cipher(d).SetIV(iv))
	return d
}

func NewEncrypter(method CipherMethod, iv string) Encrypter {
	c := NewCipher(method, iv)
	return Encrypter(c)
}

func (e Encrypter) Encrypt(dst, src []byte) (int, error) {
	c := Cipher(e)
	c.init = EVP_EncryptInit_ex
	c.update = EVP_EncryptUpdate
	c.final = EVP_EncryptFinal_ex
	if e := c.Init(); e != nil {
		return 0, e
	}
	return c.Bytes(dst, src)
}

func (e Encrypter) SetIV(iv string) Encrypter {
	e = Encrypter(Cipher(e).SetIV(iv))
	return e
}

type CBC struct {
	key string
}

func (c CBC) Key() string {
	return c.key
}

func NewAESCBC(key string) CipherMethod {
	c := CBC{
		key: key,
	}

	a := aes256cbc{c}

	return a
}

type aes256cbc struct {
	CBC
}

func (a aes256cbc) Method() EVP_CIPHER {
	return EVP_aes_256_cbc()
}

func NewDESCBC(key string) CipherMethod {
	c := CBC{
		key: key,
	}

	return descbc{c}
}

type descbc struct {
	CBC
}

func (d descbc) Method() EVP_CIPHER {
	return EVP_des_cbc()
}
