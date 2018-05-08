package main

import (
	"fmt"
	"strconv"
)

const (
	//keys should be in \x notation
	RC4OutgoingKey = "\x6a\x39\x57\x0c\xc9\xde\x4e\xc7\x1d\x64\x82\x18\x94"
	RC4IncomingKey = "\xc7\x93\x32\xb1\x97\xf9\x2b\xa8\x5e\xd2\x81\xa0\x23"
)

func main() {
	fmt.Println("Start")

	key, _ := NewCipher([]byte(RC4OutgoingKey))
	//fmt.Println([]byte(RC4IncomingKey))
	//fmt.Println([]byte(RC4OutgoingKey))
	RandomPacket := []byte{0x67, 0xb9, 0xb5, 0x97, 0x48, 0x59, 0x21, 0xba, 0xf3, 0x09, 0x25, 0x86, 0xfd, 0xed, 0x46, 0x4b, 0xae, 0xef, 0xe7, 0xbd, 0x6f, 0x5e, 0x01, 0x27, 0x26, 0x5d, 0x26, 0x5f, 0x9d, 0xaa, 0x7a, 0x8a, 0x45, 0xbb, 0xaf, 0x2b, 0x92, 0x46, 0x2d, 0xd6, 0x28, 0xc5, 0x6d, 0x95, 0x2d, 0xce, 0xf9, 0xd8, 0x64, 0x96, 0xf4, 0x9c, 0x5e, 0xbd, 0x75, 0xbb, 0xd7, 0x59, 0x8a, 0xde, 0x75, 0xc7, 0x13, 0x87, 0xd2, 0x25, 0xb1, 0xc7, 0x65, 0x68, 0xf6, 0x87, 0x69, 0x0a, 0x79, 0xb9, 0x19, 0x79, 0xe1, 0x07, 0x6a, 0x09, 0x9c, 0x21, 0xcd, 0x79, 0xcb, 0x4c, 0xda, 0x0b, 0x64, 0x19, 0x98, 0x43, 0x49, 0x0a, 0x62, 0xdc, 0x76, 0x3d, 0x11, 0x22, 0x09, 0xef, 0x22, 0x7e, 0x49, 0x6a, 0xcc, 0xf2, 0xab, 0xe7, 0x5d, 0x59, 0xbb, 0x01, 0xf7, 0xc7, 0xc7, 0x37, 0x61, 0xc0, 0x80, 0xa8, 0x67, 0xc7, 0x09, 0x3e, 0xd5, 0xd6, 0xc9, 0x49, 0x00, 0x20, 0xe0, 0x2d, 0xb1, 0x8e, 0xfb, 0x9b, 0x02, 0xdf, 0x07, 0xc1, 0x9b, 0x70, 0x11, 0xd4, 0x51, 0x45, 0xf9, 0x2d, 0x78, 0xb9, 0x9c, 0x0f, 0x73, 0x1f, 0x97, 0x17, 0xe8, 0xf4, 0x29, 0x00, 0x79, 0x84, 0x51, 0xb6, 0x0f, 0xdb, 0x36, 0x81, 0xb2, 0xd3, 0xfc, 0x1a, 0xec, 0x34, 0xc3, 0x5f, 0x63, 0xaa, 0x59, 0x36, 0x86, 0x47, 0x69, 0xd9, 0x0a, 0xc8, 0x53, 0xa0, 0x40, 0x1b, 0xf2, 0x01, 0xd0, 0x6e, 0xc7, 0x4b, 0x4a, 0xad, 0x13, 0x25, 0xf1, 0x2c, 0xa2, 0xf1, 0x65, 0xe6, 0x95, 0x6a, 0x6a, 0x20, 0x0c, 0x1d, 0xed, 0x5d, 0xe7, 0x48, 0x33, 0x54, 0xc9, 0x76, 0xf4, 0x26, 0x5d, 0x6d, 0xdd, 0x3b, 0x5a, 0x91, 0x1d, 0xa7, 0x83, 0x9d, 0xa9, 0x33, 0x98, 0x7b, 0xf4, 0x0d, 0xaf, 0x95, 0x62, 0xc0, 0x70, 0x3e, 0x17, 0x80, 0x2e, 0xfd, 0xf1, 0x54, 0x15, 0xc2, 0xbd, 0xe7, 0x0a, 0x39, 0x93, 0x2a, 0x5b, 0x8f, 0xa1, 0x22, 0xb3, 0xea, 0x1d, 0x0d, 0x2e, 0xa4, 0x14, 0xa0, 0x09, 0x27, 0x57, 0x22, 0x5b, 0x05, 0x67, 0xe2, 0x3d, 0x48, 0x0b, 0x14, 0x87, 0xb8, 0xa2, 0x5d, 0x86, 0x17, 0xe3, 0x06, 0xbc, 0x35, 0x8d, 0x59, 0xd5, 0xd5, 0x9e, 0xb7, 0x73, 0xdf, 0x15, 0xed, 0x3b, 0x9c, 0xc3, 0x02, 0x37, 0xd5, 0xd8, 0x10, 0xe7, 0x4e, 0xe3, 0x45, 0xd0, 0xa7, 0x56, 0xe0, 0xba, 0x2d, 0xad, 0xfc, 0x14, 0xdc, 0x99, 0x33, 0x60, 0xa1, 0x17, 0xf8, 0x91, 0x54, 0xcc, 0xc6, 0xe4, 0x7b, 0x8d, 0x04, 0x6b, 0x95, 0x46, 0x9c, 0xae, 0xb5, 0x4f, 0xbc, 0x0d, 0x06, 0xa9, 0x81, 0x6b, 0xb3, 0x54, 0xa7, 0x7c, 0x87, 0x6b, 0xc8, 0xfb, 0x9f, 0x4f, 0x25, 0x6b, 0x75, 0x54, 0x70, 0xb1, 0xe0, 0xab, 0x46, 0xc0, 0xbe, 0xf6, 0x77, 0x64, 0xbd, 0x5f, 0x86, 0xdd, 0x89, 0xad, 0x41, 0x16, 0xba, 0x3d, 0x88, 0xb5, 0xf1, 0x87, 0xf5, 0xb5, 0x53, 0xdb, 0xf3, 0x08, 0xc0, 0xc9, 0x43, 0x81}	
	buf := make([]byte, len(RandomPacket))
	fmt.Println("\nEncrypted:", RandomPacket)
	key.XorKeyStreamGeneric(buf, RandomPacket)
	key.Reset() //reset since we cant rewind the rc4 state for working on the same dataset
	key2, _ := NewCipher([]byte(RC4OutgoingKey))
	fmt.Println("\nDecrypted:", buf)
	key2.XorKeyStreamGeneric(RandomPacket, buf)
	fmt.Println("\nEncrypted:", RandomPacket)
	key2.Reset()

	fmt.Println("\nEnd")
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
