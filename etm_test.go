package etm

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
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

func TestOverhead(t *testing.T) {
	aead, err := NewAES128SHA256(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	expected := 56
	actual := aead.Overhead()
	if actual != expected {
		t.Errorf("Expected %v but was %v", expected, actual)
	}
}

func TestNonceSize(t *testing.T) {
	aead, err := NewAES128SHA256(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	expected := 16
	actual := aead.NonceSize()
	if actual != expected {
		t.Errorf("Expected %v but was %v", expected, actual)
	}
}

func TestBadKeySizes(t *testing.T) {
	aead, err := NewAES128SHA256(nil)
	if err == nil {
		t.Errorf("No error for 128/256, got %v instead", aead)
	}

	aead, err = NewAES192SHA256(nil)
	if err == nil {
		t.Errorf("No error for 192/256, got %v instead", aead)
	}

	aead, err = NewAES256SHA384(nil)
	if err == nil {
		t.Errorf("No error for 256/384, got %v instead", aead)
	}

	aead, err = NewAES256SHA512(nil)
	if err == nil {
		t.Errorf("No error for 256/512, got %v instead", aead)
	}

	aead, err = NewAES128SHA1(nil)
	if err == nil {
		t.Errorf("No error for 128/1, got %v instead", aead)
	}
}

func TestBadMessage(t *testing.T) {
	aead, err := NewAES128SHA256(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	input := make([]byte, 100)
	output := aead.Seal(nil, make([]byte, aead.NonceSize()), input, nil)
	output[91] ^= 3

	b, err := aead.Open(nil, make([]byte, aead.NonceSize()), output, nil)
	if err == nil {
		t.Errorf("Expected error but got %v", b)
	}
}

func TestAEAD_AES_128_CBC_HMAC_SHA_256(t *testing.T) {
	aead, err := NewAES128SHA256(decode(`
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

	expected := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79
a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9
a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2
fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36
09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8
6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b
38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f
bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5
4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db
65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4
`)

	c := aead.Seal(nil, iv, p, a)
	if !bytes.Equal(expected, c) {
		t.Errorf("Expected \n%x\n but was \n%x", expected, c)
	}

	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func TestAEAD_AES_192_CBC_HMAC_SHA_256(t *testing.T) {
	aead, err := NewAES192SHA256(decode(`
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

	expected := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
ea 65 da 6b 59 e6 1e db 41 9b e6 2d 19 71 2a e5
d3 03 ee b5 00 52 d0 df d6 69 7f 77 22 4c 8e db
00 0d 27 9b dc 14 c1 07 26 54 bd 30 94 42 30 c6
57 be d4 ca 0c 9f 4a 84 66 f2 2b 22 6d 17 46 21
4b f8 cf c2 40 0a dd 9f 51 26 e4 79 66 3f c9 0b
3b ed 78 7a 2f 0f fc bf 39 04 be 2a 64 1d 5c 21
05 bf e5 91 ba e2 3b 1d 74 49 e5 32 ee f6 0a 9a
c8 bb 6c 6b 01 d3 5d 49 78 7b cd 57 ef 48 49 27
f2 80 ad c9 1a c0 c4 e7 9c 7b 11 ef c6 00 54 e3
84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20
75 16 80 39 cc c7 33 d7
`)

	c := aead.Seal(nil, iv, p, a)
	if !bytes.Equal(expected, c) {
		t.Errorf("Expected \n%x\n but was \n%x", expected, c)
	}

	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func TestAEAD_AES_256_CBC_HMAC_SHA_384(t *testing.T) {
	aead, err := NewAES256SHA384(decode(`
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

	expected := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
89 31 29 b0 f4 ee 9e b1 8d 75 ed a6 f2 aa a9 f3
60 7c 98 c4 ba 04 44 d3 41 62 17 0d 89 61 88 4e
58 f2 7d 4a 35 a5 e3 e3 23 4a a9 94 04 f3 27 f5
c2 d7 8e 98 6e 57 49 85 8b 88 bc dd c2 ba 05 21
8f 19 51 12 d6 ad 48 fa 3b 1e 89 aa 7f 20 d5 96
68 2f 10 b3 64 8d 3b b0 c9 83 c3 18 5f 59 e3 6d
28 f6 47 c1 c1 39 88 de 8e a0 d8 21 19 8c 15 09
77 e2 8c a7 68 08 0b c7 8c 35 fa ed 69 d8 c0 b7
d9 f5 06 23 21 98 a4 89 a1 a6 ae 03 a3 19 fb 30
dd 13 1d 05 ab 34 67 dd 05 6f 8e 88 2b ad 70 63
7f 1e 9a 54 1d 9c 23 e7
`)

	c := aead.Seal(nil, iv, p, a)
	if !bytes.Equal(expected, c) {
		t.Errorf("Expected \n%x\n but was \n%x", expected, c)
	}

	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func TestAEAD_AES_256_CBC_HMAC_SHA_512(t *testing.T) {
	aead, err := NewAES256SHA512(decode(`
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

	expected := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd
3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd
82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2
e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b
36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1
1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3
a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e
31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b
be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6
4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf
2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5
`)

	c := aead.Seal(nil, iv, p, a)
	if !bytes.Equal(expected, c) {
		t.Errorf("Expected \n%x\n but was \n%x", expected, c)
	}

	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func TestAEAD_AES_128_CBC_HMAC_SHA1(t *testing.T) {
	aead, err := NewAES128SHA1(decode(`
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

	expected := decode(`
1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04
c6 3a ec 99 63 f4 ff 33 a8 5e 56 4c d0 5f 92 40
0a 71 fe 98 bc b3 39 ac c1 d7 8c 92 b3 aa 6a 32
14 60 d2 ae ce c4 3b 78 4b 3b 08 b8 30 be 52 91
dc 04 00 b8 af c6 cd 1c 84 75 76 46 32 a8 36 05
01 e5 31 9a 12 81 27 ae 4b 0e aa 9b 2f 97 ea 6d
f0 22 00 d6 f6 8c 74 3b 79 4e d5 d6 13 9e 84 c4
cb 91 9e bb 8d 82 56 09 8b 63 85 e4 14 76 c4 16
cf c8 5a 46 fa c4 0e a4 50 d2 b4 c0 fd 7e 03 dc
d8 33 c8 c3 d2 13 5f 0d 10 9b d2 31 80 8b b3 fd
4d 9d f6 8e 54 f7 d9 7e 91 4b 4a 9d
`)

	c := aead.Seal(nil, iv, p, a)
	if !bytes.Equal(expected, c) {
		t.Errorf("Expected \n%x\n but was \n%x", expected, c)
	}

	p2, err := aead.Open(nil, iv, c, a)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p, p2) {
		t.Error("Bad round-trip")
	}
}

func Example() {
	key := []byte("yellow submarine was a love song")
	plaintext := []byte("this is a secret value")
	data := []byte("this is a public value")

	aead, err := NewAES128SHA256(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	nonce := make([]byte, aead.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	ciphertext := aead.Seal(nil, nonce, plaintext, data)

	secret, err := aead.Open(nil, nil, ciphertext, data)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(secret))
	// Output:
	// this is a secret value
}
