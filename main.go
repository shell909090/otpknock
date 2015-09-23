package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

var (
	errPerm   = errors.New("config file should't read or write by others.")
	errConfig = errors.New("config file wrong")
)

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

	fi, err := file.Stat()
	if err != nil {
		return
	}

	fm := fi.Mode()
	if (fm.Perm() & 0x3f) != 0 {
		err = errPerm
		return
	}

	dec := json.NewDecoder(file)
	err = dec.Decode(&cfg)
	if err != nil {
		return
	}

	if cfg.Addr == "" {
		cfg.Addr = ":37798"
	}
	if cfg.Secret == "" || cfg.OpenCmd == "" {
		err = errConfig
		return
	}
	if len(cfg.Emergency) == 0 {
		fmt.Println("run without emergency, may be dangerous.")
	}
	if cfg.Interval == 0 {
		cfg.Interval = 30
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

func FilterEmergency(token string) {
	new_one := make([]string, 0)
	for _, emerg := range cfg.Emergency {
		if token != emerg {
			new_one = append(new_one, emerg)
		}
	}
	cfg.Emergency = new_one
	return
}

func Verify(buf []byte) bool {
	totp := &otp.TOTP{Secret: cfg.Secret, IsBase32Secret: true}

	token := string(buf)
	token = strings.Trim(token, "\r\n")
	fmt.Printf("begin verify: %s.\n", token)
	if totp.Verify(token) {
		fmt.Println("verified by totp.")
		return true
	}
	for _, emerg := range cfg.Emergency {
		if token == emerg {
			FilterEmergency(token)
			fmt.Println("verified by emergency, remember to change it.")
			return true
		}
	}
	fmt.Println("verify failed.")
	return false
}

func TryOpenDoor(buf []byte, raddr *net.UDPAddr) {
	fmt.Printf("got data from %s.\n", raddr.String())
	if !Verify(buf) {
		return
	}

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

	time.Sleep(time.Duration(cfg.Interval) * time.Second)

	fmt.Printf("close door for %s.\n", raddr.String())
	err = RunCmd(CloseCmd)
	if err != nil {
		fmt.Printf("close exec Error: %s.\n", err.Error())
		return
	}
}

func main() {
	config, err := LoadConfig()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	cfg = &config

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

	fmt.Println("started.")
	for {
		buf := make([]byte, 65536)
		n, raddr, err := sock.ReadFromUDP(buf)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}

		go TryOpenDoor(buf[:n], raddr)
	}
}
