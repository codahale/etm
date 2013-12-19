// Package etm provides a set of Encrypt-Then-Mac AEAD implementations, which
// combine block ciphers like AES with HMACs.
//
// The AEAD (Athenticated Encryption with Associated Data) construction provides
// a unified API for sealing messages in a way which provides both
// confidentiality *and* integrity. Unlike unauthenticated modes like CBC,
// AEAD algorithms are resistant to chosen ciphertext attacks, such as padding
// oracle attacks, etc., and add only a small amount of overhead.
//
// See http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-02 for
// technical details.
package etm

// BUG(codahale): This package has not been validated against any test vectors.
// The test vectors in draft-mcgrew-aead-aes-cbc-hmac-sha2-02 don't appear to
// work.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
)

// NewAES128CBCHMACSHA256 returns an AES_128_CBC_HMAC_SHA_256 AEAD instance
// given a 32-byte key or an error if the key is the wrong size.
func NewAES128CBCHMACSHA256(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("etm: key must be 32 bytes long")
	}
	encKey, macKey := split(key, 16, 16)
	return &etmAEAD{
		blockSize: aes.BlockSize,
		encKey:    encKey,
		macKey:    macKey,
		encAlg:    aes.NewCipher,
		macAlg:    sha256.New,
		tagSize:   16,
	}, nil
}

// NewAES192CBCHMACSHA256 returns an AES_192_CBC_HMAC_SHA_256 AEAD instance
// given a 48-byte key or an error if the key is the wrong size.
func NewAES192CBCHMACSHA256(key []byte) (cipher.AEAD, error) {
	if len(key) != 48 {
		return nil, errors.New("etm: key must be 48 bytes long")
	}
	encKey, macKey := split(key, 24, 24)
	return &etmAEAD{
		blockSize: aes.BlockSize,
		encKey:    encKey,
		macKey:    macKey,
		encAlg:    aes.NewCipher,
		macAlg:    sha256.New,
		tagSize:   24,
	}, nil
}

// NewAES256CBCHMACSHA384 returns an AES_256_CBC_HMAC_SHA_384 AEAD instance
// given a 56-byte key or an error if the key is the wrong size.
func NewAES256CBCHMACSHA384(key []byte) (cipher.AEAD, error) {
	if len(key) != 56 {
		return nil, errors.New("etm: key must be 56 bytes long")
	}
	encKey, macKey := split(key, 32, 24)
	return &etmAEAD{
		blockSize: aes.BlockSize,
		encKey:    encKey,
		macKey:    macKey,
		encAlg:    aes.NewCipher,
		macAlg:    sha512.New384,
		tagSize:   24,
	}, nil
}

// NewAES256CBCHMACSHA512 returns an AES_256_CBC_HMAC_SHA_512 AEAD instance
// given a 64-byte key or an error if the key is the wrong size.
func NewAES256CBCHMACSHA512(key []byte) (cipher.AEAD, error) {
	if len(key) != 64 {
		return nil, errors.New("etm: key must be 64 bytes long")
	}
	encKey, macKey := split(key, 32, 32)
	return &etmAEAD{
		blockSize: aes.BlockSize,
		encKey:    encKey,
		macKey:    macKey,
		encAlg:    aes.NewCipher,
		macAlg:    sha512.New,
		tagSize:   32,
	}, nil
}

// NewAES128CBCHMACSHA1 returns an AES_128_CBC_HMAC_SHA1 AEAD instance
// given a 36-byte key or an error if the key is the wrong size.
func NewAES128CBCHMACSHA1(key []byte) (cipher.AEAD, error) {
	if len(key) != 36 {
		return nil, errors.New("etm: key must be 36 bytes long")
	}
	encKey, macKey := split(key, 16, 20)
	return &etmAEAD{
		blockSize: aes.BlockSize,
		encKey:    encKey,
		macKey:    macKey,
		encAlg:    aes.NewCipher,
		macAlg:    sha256.New,
		tagSize:   12,
	}, nil
}

type blockFunc func(key []byte) (cipher.Block, error)

type hashFunc func() hash.Hash

type etmAEAD struct {
	blockSize, tagSize int
	encKey, macKey     []byte
	encAlg             blockFunc
	macAlg             hashFunc
}

func (aead *etmAEAD) Overhead() int {
	return aead.blockSize + aead.tagSize + 8
}

func (aead *etmAEAD) NonceSize() int {
	return aead.blockSize
}

func (aead *etmAEAD) Seal(dst, nonce, plaintext, data []byte) []byte {
	ps := make([]byte, aead.blockSize-(len(plaintext)%aead.blockSize))
	for i := range ps {
		ps[i] = byte(len(ps))
	}

	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(data)*8))

	b, err := aead.encAlg(aead.encKey)
	if err != nil {
		panic(err)
	}

	c := cipher.NewCBCEncrypter(b, nonce)
	i := append(plaintext, ps...)
	s := make([]byte, len(i))
	c.CryptBlocks(s, i)

	h := hmac.New(aead.macAlg, aead.macKey)
	h.Write(data)
	h.Write(s)
	h.Write(al)
	t := h.Sum(nil)[:aead.tagSize]

	return append(dst, append(s, t...)...)
}

func (aead *etmAEAD) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	s := ciphertext[:(len(ciphertext) - aead.tagSize)]
	t := ciphertext[len(ciphertext)-aead.tagSize:]

	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(data)*8))

	h := hmac.New(aead.macAlg, aead.macKey)
	h.Write(data)
	h.Write(s)
	h.Write(al)
	t2 := h.Sum(nil)[:aead.tagSize]

	if subtle.ConstantTimeCompare(t, t2) != 1 {
		return nil, errors.New("etm: message authentication failed")
	}

	b, err := aead.encAlg(aead.encKey)
	if err != nil {
		return nil, err
	}

	c := cipher.NewCBCDecrypter(b, nonce)
	o := make([]byte, len(s))
	c.CryptBlocks(o, s)

	return o[:len(o)-int(o[len(o)-1])], nil
}

func split(key []byte, encKeyLen, macKeyLen int) ([]byte, []byte) {
	return key[0:encKeyLen], key[len(key)-macKeyLen:]
}