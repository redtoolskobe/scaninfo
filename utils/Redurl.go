package utils

import (
	"bufio"
	"log"
	"os"
	"strings"

	"github.com/gookit/color"
)

func GetUrlList(filename string) (urls []string) {
	if filename == "" {
		return
	}
	file, err := os.Open(filename)
	if err != nil {
		log.Println("Local URLfile read error:", err)
		color.RGBStyleFromString("237,64,35").Println("[error] the input file is wrong!!!")
		os.Exit(1)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "http") {
			urls = append(urls, scanner.Text())
		} else {
			urls = append(urls, "http://"+scanner.Text())
		}
	}
	return
}
