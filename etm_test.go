package etm

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"regexp"
	"testing"
)

var _ cipher.AEAD = &etmAEAD{}

var whitespace = regexp.MustCompile(`[\s]+`)

func decode(s string) []byte {
	b, err := hex.DecodeString(whitespace.ReplaceAllString(s, ""))
	if err != nil {
		panic(err)
	}
	return b
}

func TestAEAD_AES_128_CBC_HMAC_SHA_256(t *testing.T) {
	aead, err := NewAES128CBCHMACSHA256(decode(`
10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
`))
	if err != nil {
		t.Fatal(err)
	}

	p := decode(`
41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65
`)

	iv := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
`)

	a := decode(`
54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
4b 65 72 63 6b 68 6f 66 66 73
`)

	c := aead.Seal(nil, iv, p, a)
	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func TestAEAD_AES_192_CBC_HMAC_SHA_256(t *testing.T) {
	aead, err := NewAES192CBCHMACSHA256(decode(`
18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27
28 29 2a 2b 2c 2d 2e 2f
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
10 11 12 13 14 15 16 17
`))
	if err != nil {
		t.Fatal(err)
	}

	p := decode(`
41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65
`)

	iv := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
`)

	a := decode(`
54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
4b 65 72 63 6b 68 6f 66 66 73
`)

	c := aead.Seal(nil, iv, p, a)
	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func TestAEAD_AES_256_CBC_HMAC_SHA_384(t *testing.T) {
	aead, err := NewAES256CBCHMACSHA384(decode(`
18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27
28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
10 11 12 13 14 15 16 17
`))
	if err != nil {
		t.Fatal(err)
	}

	p := decode(`
41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65
`)

	iv := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
`)

	a := decode(`
54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
4b 65 72 63 6b 68 6f 66 66 73
`)

	c := aead.Seal(nil, iv, p, a)
	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func TestAEAD_AES_256_CBC_HMAC_SHA_512(t *testing.T) {
	aead, err := NewAES256CBCHMACSHA512(decode(`
20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
`))
	if err != nil {
		t.Fatal(err)
	}

	p := decode(`
41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65
`)

	iv := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
`)

	a := decode(`
54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
4b 65 72 63 6b 68 6f 66 66 73
`)

	c := aead.Seal(nil, iv, p, a)
	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func TestAEAD_AES_128_CBC_HMAC_SHA1(t *testing.T) {
	aead, err := NewAES128CBCHMACSHA1(decode(`
14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
10 11 12 13
`))
	if err != nil {
		t.Fatal(err)
	}

	p := decode(`
41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65
`)

	iv := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
`)

	a := decode(`
54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
4b 65 72 63 6b 68 6f 66 66 73
`)

	c := aead.Seal(nil, iv, p, a)
	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}
