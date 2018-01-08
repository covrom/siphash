package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

// Hash returns the 64-bit SipHash-2-4 of the given byte slice with two 64-bit
// parts of 128-bit key: k0 and k1.
func Hash(k0, k1 uint64, p []byte) uint64 {
	// Initialization.
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573
	t := uint64(len(p)) << 56

	// Compression.
	for len(p) >= 8 {
		m := uint64(p[0]) | uint64(p[1])<<8 | uint64(p[2])<<16 | uint64(p[3])<<24 |
			uint64(p[4])<<32 | uint64(p[5])<<40 | uint64(p[6])<<48 | uint64(p[7])<<56
		v3 ^= m

		// Round 1.
		v0 += v1
		v1 = v1<<13 | v1>>(64-13)
		v1 ^= v0
		v0 = v0<<32 | v0>>(64-32)

		v2 += v3
		v3 = v3<<16 | v3>>(64-16)
		v3 ^= v2

		v0 += v3
		v3 = v3<<21 | v3>>(64-21)
		v3 ^= v0

		v2 += v1
		v1 = v1<<17 | v1>>(64-17)
		v1 ^= v2
		v2 = v2<<32 | v2>>(64-32)

		// Round 2.
		v0 += v1
		v1 = v1<<13 | v1>>(64-13)
		v1 ^= v0
		v0 = v0<<32 | v0>>(64-32)

		v2 += v3
		v3 = v3<<16 | v3>>(64-16)
		v3 ^= v2

		v0 += v3
		v3 = v3<<21 | v3>>(64-21)
		v3 ^= v0

		v2 += v1
		v1 = v1<<17 | v1>>(64-17)
		v1 ^= v2
		v2 = v2<<32 | v2>>(64-32)

		v0 ^= m
		p = p[8:]
	}

	// Compress last block.
	switch len(p) {
	case 7:
		t |= uint64(p[6]) << 48
		fallthrough
	case 6:
		t |= uint64(p[5]) << 40
		fallthrough
	case 5:
		t |= uint64(p[4]) << 32
		fallthrough
	case 4:
		t |= uint64(p[3]) << 24
		fallthrough
	case 3:
		t |= uint64(p[2]) << 16
		fallthrough
	case 2:
		t |= uint64(p[1]) << 8
		fallthrough
	case 1:
		t |= uint64(p[0])
	}

	v3 ^= t

	// Round 1.
	v0 += v1
	v1 = v1<<13 | v1>>(64-13)
	v1 ^= v0
	v0 = v0<<32 | v0>>(64-32)

	v2 += v3
	v3 = v3<<16 | v3>>(64-16)
	v3 ^= v2

	v0 += v3
	v3 = v3<<21 | v3>>(64-21)
	v3 ^= v0

	v2 += v1
	v1 = v1<<17 | v1>>(64-17)
	v1 ^= v2
	v2 = v2<<32 | v2>>(64-32)

	// Round 2.
	v0 += v1
	v1 = v1<<13 | v1>>(64-13)
	v1 ^= v0
	v0 = v0<<32 | v0>>(64-32)

	v2 += v3
	v3 = v3<<16 | v3>>(64-16)
	v3 ^= v2

	v0 += v3
	v3 = v3<<21 | v3>>(64-21)
	v3 ^= v0

	v2 += v1
	v1 = v1<<17 | v1>>(64-17)
	v1 ^= v2
	v2 = v2<<32 | v2>>(64-32)

	v0 ^= t

	// Finalization.
	v2 ^= 0xff

	// Round 1.
	v0 += v1
	v1 = v1<<13 | v1>>(64-13)
	v1 ^= v0
	v0 = v0<<32 | v0>>(64-32)

	v2 += v3
	v3 = v3<<16 | v3>>(64-16)
	v3 ^= v2

	v0 += v3
	v3 = v3<<21 | v3>>(64-21)
	v3 ^= v0

	v2 += v1
	v1 = v1<<17 | v1>>(64-17)
	v1 ^= v2
	v2 = v2<<32 | v2>>(64-32)

	// Round 2.
	v0 += v1
	v1 = v1<<13 | v1>>(64-13)
	v1 ^= v0
	v0 = v0<<32 | v0>>(64-32)

	v2 += v3
	v3 = v3<<16 | v3>>(64-16)
	v3 ^= v2

	v0 += v3
	v3 = v3<<21 | v3>>(64-21)
	v3 ^= v0

	v2 += v1
	v1 = v1<<17 | v1>>(64-17)
	v1 ^= v2
	v2 = v2<<32 | v2>>(64-32)

	// Round 3.
	v0 += v1
	v1 = v1<<13 | v1>>(64-13)
	v1 ^= v0
	v0 = v0<<32 | v0>>(64-32)

	v2 += v3
	v3 = v3<<16 | v3>>(64-16)
	v3 ^= v2

	v0 += v3
	v3 = v3<<21 | v3>>(64-21)
	v3 ^= v0

	v2 += v1
	v1 = v1<<17 | v1>>(64-17)
	v1 ^= v2
	v2 = v2<<32 | v2>>(64-32)

	// Round 4.
	v0 += v1
	v1 = v1<<13 | v1>>(64-13)
	v1 ^= v0
	v0 = v0<<32 | v0>>(64-32)

	v2 += v3
	v3 = v3<<16 | v3>>(64-16)
	v3 ^= v2

	v0 += v3
	v3 = v3<<21 | v3>>(64-21)
	v3 ^= v0

	v2 += v1
	v1 = v1<<17 | v1>>(64-17)
	v1 ^= v2
	v2 = v2<<32 | v2>>(64-32)

	return v0 ^ v1 ^ v2 ^ v3
}

var syms = []byte(" 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\n")
var symSpaces = []byte("    \n   ")

func cmp(chin chan [][]byte) {
	for {
		s := <-chin

		if *logWords {
			fmt.Println(string(s[0]), string(s[1]))
		}

		if Hash(0xdda7806a4847ec61, 0xb5940c2623a5aabd, s[0]) == Hash(0xdda7806a4847ec61, 0xb5940c2623a5aabd, s[1]) {
			if !bytes.Equal(s[0], s[1]) {
				fmt.Printf("Equal hash: %q == %q\n", s[0], s[1])
			}
		}
	}
}

var (
	combineWords = flag.Uint64("n", 1, "максимальное количество слов для составления фразы")
	rndWords     = flag.Bool("rnd", false, "составление случайных строк из набора ASCII")
	logWords     = flag.Bool("log", false, "логировать формируемые слова")

	words = make([]string, 0)
)

func RndWords() (rv []byte) {
	var i uint64
	binary.Read(rand.Reader, binary.LittleEndian, &i)
	cnt := i%*combineWords + 1
	for n := uint64(0); n < cnt; n++ {
		binary.Read(rand.Reader, binary.LittleEndian, &i)
		m := i % uint64(len(words))
		rv = append(rv, []byte(words[m])...)
		if n < cnt-1 {
			binary.Read(rand.Reader, binary.LittleEndian, &i)
			sp := i % uint64(len(symSpaces))
			rv = append(rv, symSpaces[sp])
		}
	}
	return
}

func main() {
	flag.Parse()
	args := flag.Args()
	if !*rndWords && len(args) == 0 {
		log.Fatal("Укажите файл с json-массивом слов")
	}

	if !*rndWords {
		fw, err := os.Open(args[0])
		if err != nil {
			log.Fatal(err)
		}
		dec := json.NewDecoder(fw)
		if err := dec.Decode(&words); err != nil {
			fw.Close()
			log.Fatal(err)
		}
		fw.Close()
		if len(words) == 0 {
			log.Fatal("В файле нет json-массива слов")
		}
	}

	lens := make([]byte, 2)

	chin := make(chan [][]byte, 100)

	go cmp(chin)
	go cmp(chin)
	go cmp(chin)
	go cmp(chin)

	cnt := uint64(0)

	for {
		if cnt%10000000 == 0 {
			fmt.Println(cnt)
		}

		s := make([][]byte, 2)

		if *rndWords {
			rand.Read(lens)
			if lens[0] == 0 {
				lens[0] = 1
			}
			if lens[1] == 0 {
				lens[1] = 1
			}
			s[0] = make([]byte, lens[0])
			s[1] = make([]byte, lens[1])
			rand.Read(s[0])
			rand.Read(s[1])
			for i, b := range s[0] {
				s[0][i] = syms[b&0x3f]
			}
			for i, b := range s[1] {
				s[1][i] = syms[b&0x3f]
			}
		} else {
			s[0] = RndWords()
			s[1] = RndWords()
		}

		chin <- s
		cnt++
		if cnt > 1<<32 {
			break
		}
	}
	fmt.Println("Done!")
}
