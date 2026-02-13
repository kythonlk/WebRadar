package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var symbols = []string{
	"!", "@", "#", "$", "%", "&", "*", "_", "-", ".",
}

var commonSuffix = []string{
	"123", "1234", "2023", "2024", "2025", "2026", "2027", "007", "01",
}

func main() {

	inputFile := flag.String("i", "input.txt", "Input file")
	outputFile := flag.String("o", "output.txt", "Output file")
	generate := flag.Int("g", 0, "Generate N variations per word")
	flag.Parse()

	file, err := os.Open(*inputFile)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	wordRegex := regexp.MustCompile(`[\p{L}\p{N}]+`)
	unique := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		words := wordRegex.FindAllString(scanner.Text(), -1)
		for _, w := range words {
			w = strings.ToLower(w)
			unique[w] = struct{}{}
		}
	}

	outputSet := make(map[string]struct{})

	for word := range unique {
		outputSet[word] = struct{}{}

		if *generate > 0 {
			generateVariants(word, *generate, outputSet)
		}
	}

	var finalList []string
	for w := range outputSet {
		finalList = append(finalList, w)
	}

	sort.Strings(finalList)

	out, err := os.Create(*outputFile)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	for _, w := range finalList {
		writer.WriteString(w + "\n")
	}
	writer.Flush()

	fmt.Printf("Done. %d words written to %s\n", len(finalList), *outputFile)
}

func generateVariants(word string, limit int, out map[string]struct{}) {

	count := 0

	add := func(v string) {
		if count >= limit {
			return
		}
		if _, exists := out[v]; !exists {
			out[v] = struct{}{}
			count++
		}
	}

	// Case variations
	add(strings.ToUpper(word))
	caser := cases.Title(language.English)
	add(caser.String(word))

	// Leetspeak
	leet := leetReplace(word)
	add(leet)

	// Number suffix
	for i := 0; i < 10 && count < limit; i++ {
		add(fmt.Sprintf("%s%d", word, i))
	}

	// Symbol suffix
	for _, s := range symbols {
		if count >= limit {
			break
		}
		add(word + s)
		add(s + word)
	}

	// Common suffixes
	for _, s := range commonSuffix {
		if count >= limit {
			break
		}
		add(word + s)
	}

	// Combined symbol + number
	for _, s := range symbols {
		if count >= limit {
			break
		}
		add(word + s + "123")
	}
}

func leetReplace(word string) string {
	replacer := strings.NewReplacer(
		"a", "4",
		"e", "3",
		"i", "1",
		"o", "0",
		"s", "5",
		"t", "7",
	)
	return replacer.Replace(word)
}
