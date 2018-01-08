package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

var (
	outfile = flag.String("o", "words.json", "выходной файл json с массивом слов")
	chpath  = make(chan string, 100)
	wg      = &sync.WaitGroup{}
	words   = make([]string, 0)
	chw     = make(chan string, 10000)
	donew   = make(chan bool)
	mu      = sync.RWMutex{}
)

func isSpace(r rune) bool {
	if r <= '\u00FF' {
		// Obvious ASCII ones: \t through \r plus space. Plus two Latin-1 oddballs.
		if (r < '0' || (r > '9' && r < '@') || (r > 'Z' && r < 'a') || r > 'z') && (r != '-') && (r != '_') && (r != '.') {
			return true
		}
		switch r {
		case '\u0085', '\u00A0':
			return true
		}
		return false
	}
	// High-valued ones.
	if '\u2000' <= r && r <= '\u200a' {
		return true
	}
	switch r {
	case '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000':
		return true
	}

	if (r < 'А' || r > 'я') && (r != 0x0451) && (r != 0x0401) {
		return true
	}

	return false
}

func ScanWords(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading spaces.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !isSpace(r) {
			break
		}
	}
	// Scan until space, marking end of word.
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])
		if isSpace(r) {
			return i + width, data[start:i], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		return len(data), data[start:], nil
	}
	// Request more data.
	return start, nil, nil
}

func Parse() {
	for s := range chpath {
		f, err := os.Open(s)
		if err != nil {
			log.Printf("Ошибка обработки файла: %s\n", s)
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Split(ScanWords)
		for scanner.Scan() {
			w := scanner.Text()
			if len(w) < 256 {
				chw <- w
			}
		}
		if err := scanner.Err(); err != nil {
			log.Println("Ошибка при разборе файла:", s, err)
		} else {
			log.Println(s)
		}
		f.Close()
	}
	wg.Done()
}

func WriteToWords() {
	for w := range chw {
		i := sort.SearchStrings(words, w)
		if i == len(words) {
			words = append(words, w)
		} else if words[i] != w {
			words = append(words, "")
			copy(words[i+1:], words[i:])
			words[i] = w
		}
	}
	donew <- true
}

func ParseFile(p string, info os.FileInfo, err error) error {
	ext := filepath.Ext(p)
	if !info.IsDir() && len(ext) > 0 && strings.Contains(".go.txt.s.xml.html.htm.js.css", ext) {
		chpath <- p
	}
	return nil
}

func main() {
	flag.Parse()

	args := flag.Args()

	if len(args) == 0 {
		log.Fatal("Укажите путь/пути для парсинга")
	}

	fo, err := os.Open(*outfile)
	if err == nil {
		dec := json.NewDecoder(fo)
		if dec.Decode(&words) != nil {
			fmt.Println("Создаем новый словарь", *outfile)
			words = make([]string, 0)
		} else {
			fmt.Println("Добавляем в словарь", *outfile)
		}
	}

	go WriteToWords()

	wg.Add(4)
	go Parse()
	go Parse()
	go Parse()
	go Parse()

	for _, arg := range args {
		filepath.Walk(arg, ParseFile)
	}

	close(chpath)

	wg.Wait()

	close(chw)
	<-donew

	fo.Close()
	fw, err := os.Create(*outfile)
	if err != nil {
		log.Fatal("Невозможно сохранить результат в файле ", outfile)
	}
	enc := json.NewEncoder(fw)
	enc.Encode(words)
	fw.Close()

	log.Println("Завершено!")
}
