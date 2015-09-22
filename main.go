package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	otp "github.com/hgfischer/go-otp"
)

// CAUTION: DO NOT PROTECT SYSTEM FROM BLIND GUESS.
// attacker could use that as DOS attack.
// they can spoof their source IP address.
type Config struct {
	Secret    string
	Emergency []string
	Addr      string
	OpenCmd   string
	CloseCmd  string
	Interval  uint16
}

var cfg *Config = nil

func LoadConfig() (cfg Config, err error) {
	var configfile string
	flag.StringVar(&configfile, "config", "/etc/otpknock.json", "config file")
	flag.Parse()

	file, err := os.Open(configfile)
	if err != nil {
		return
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	err = dec.Decode(&cfg)
	if err != nil {
		return
	}

	if cfg.Addr == "" {
		cfg.Addr = ":37798"
	}
	return
}

func RenderTemplate(t string, raddr *net.UDPAddr) (s string, err error) {
	tmpl, err := template.New("t").Parse(t)
	if err != nil {
		return
	}

	buf := bytes.NewBufferString("")
	err = tmpl.Execute(buf, raddr)
	return buf.String(), nil
}

func RunCmd(s string) (err error) {
	fmt.Printf("run: %s.\n", s)
	cmd := exec.Command("/bin/sh", "-c", s)
	return cmd.Run()
}

func OpenDoor(raddr *net.UDPAddr) {
	OpenCmd, err := RenderTemplate(cfg.OpenCmd, raddr)
	if err != nil {
		fmt.Printf("open template Error: %s.\n", err.Error())
		return
	}

	CloseCmd, err := RenderTemplate(cfg.CloseCmd, raddr)
	if err != nil {
		fmt.Printf("close template Error: %s.\n", err.Error())
		return
	}

	fmt.Printf("open door for %s.\n", raddr.String())
	err = RunCmd(OpenCmd)
	if err != nil {
		fmt.Printf("open exec Error: %s.\n", err.Error())
		return
	}

	go func() {
		time.Sleep(time.Duration(cfg.Interval) * time.Second)

		fmt.Printf("close door for %s.\n", raddr.String())
		err := RunCmd(CloseCmd)
		if err != nil {
			fmt.Printf("close exec Error: %s.\n", err.Error())
			return
		}
	}()
}

func Verify(buf []byte, totp *otp.TOTP) bool {
	token := string(buf)
	token = strings.Trim(token, "\r\n")
	fmt.Printf("begin verify: %s.\n", token)
	if totp.Verify(token) {
		fmt.Println("verified by totp.")
		return true
	}
	for _, emerg := range cfg.Emergency {
		if token == emerg {
			fmt.Println("verified by emergency, remember to change it.")
			return true
		}
	}
	fmt.Println("verify failed.")
	return false
}

func Work() {
	laddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	sock, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer sock.Close()

	totp := &otp.TOTP{Secret: cfg.Secret, IsBase32Secret: true}
	buf := make([]byte, 65536)
	fmt.Println("started.")
	for {
		n, raddr, err := sock.ReadFromUDP(buf)
		fmt.Printf("got data from %s.\n", raddr.String())
		if err != nil {
			fmt.Println(err.Error())
			continue
		}

		if Verify(buf[:n], totp) {
			OpenDoor(raddr)
		}
	}
}

func main() {
	config, err := LoadConfig()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	cfg = &config

	Work()
}
