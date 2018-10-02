package main

import (
	"fmt"
	"strconv"
)

const (
	//keys should be in \x notation
	RC4_Key = "\x6a\x39\x57\x0c\xc9\xde\x4e\xc7\x1d\x64\x82\x18\x94"
)

func main() {
	fmt.Println("Start")

	key, _ := NewCipher([]byte(RC4_Key)) //initialize our cipher with the given key
	
	RandomData := "Hello World"

	buf := make([]byte, len(RandomData))
	for i, v := range RandomData {
		buf[i] = byte(v)
	}
	fmt.Println("Plaintext:", buf)
	fmt.Println("Plaintext string:", string(buf))

	key.XorKeyStreamGeneric(buf, buf) //encrypt the data
	fmt.Println("Encrypted:", buf)
	fmt.Println("Encrypted string:", string(buf))
	key.Reset() //reset since we cant rewind the rc4 state for working on the same dataset

	key2, _ := NewCipher([]byte(RC4_Key))
	key2.XorKeyStreamGeneric(buf, buf)
	fmt.Println("Decrypted:", buf)
	fmt.Println("Decrypted string:", string(buf))
	key2.Reset()

	fmt.Println("End")
}

func CipherData(data []byte, ciph *Cipher) []byte {
	buffer := make([]byte, len(data))
	ciph.XorKeyStreamGeneric(buffer, data)
	return buffer
}

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license

type Cipher struct {
	s [256]uint32
	i, j uint8
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/rc4: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (*Cipher, error) {
	k := len(key)
	if k < 1 || k > 256 {
		return nil, KeySizeError(k)
	}
	var c Cipher
	for i := 0; i < 256; i++ {
		c.s[i] = uint32(i)
	}
	var j uint8 = 0
	for i := 0; i < 256; i++ {

		j += uint8(c.s[i]) + key[i%k]

		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return &c, nil
}

func (c *Cipher) Reset() {
	for i := range c.s {
		c.s[i] = 0
	}
	c.i, c.j = 0, 0
}

func (c *Cipher)XorKeyStreamGeneric(dst, src []byte) {
	i, j := c.i, c.j
	for k, v := range src {
		i += 1
		j += uint8(c.s[i])
		c.s[i], c.s[j] = c.s[j], c.s[i]
		dst[k] = v ^ uint8(c.s[uint8(c.s[i]+c.s[j])])
	}
	c.i, c.j = i, j
}
