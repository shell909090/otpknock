// Copyright (c) 2015, Shell.Xu <shell909090@gmail.com>
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"html/template"
	"log"
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
	errConfig = errors.New("config file wrong")

	Info   = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
)

type Config struct {
	Secret       string
	Emergency    []string
	EmergencySet map[string]struct{} `json:"-"`
	Addr         string
	OpenCmd      string
	CloseCmd     string
	Interval     uint32
}

var cfg *Config = nil

func LoadConfig() (cfg *Config, err error) {
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

	if (fi.Mode().Perm() & 0x3f) != 0 {
		Info.Printf("config file should't read or write by others.")
	}

	cfg = &Config{}
	dec := json.NewDecoder(file)
	err = dec.Decode(cfg)
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
		Info.Printf("run without emergency, may be dangerous.")
	}
	cfg.EmergencySet = make(map[string]struct{}, 0)
	for _, emerg := range cfg.Emergency {
		cfg.EmergencySet[emerg] = struct{}{}
	}

	if cfg.Interval == 0 {
		cfg.Interval = 30
	}
	return
}

func RenderTemplate(t string, raddr *net.UDPAddr) (string, error) {
	tmpl, err := template.New("").Parse(t)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBufferString("")
	err = tmpl.Execute(buf, raddr)
	return buf.String(), nil
}

func RunCmd(s string) error {
	Info.Printf("run: %s.", s)
	cmd := exec.Command("/bin/sh", "-c", s)
	return cmd.Run()
}

func Verify(buf []byte) bool {
	totp := &otp.TOTP{Secret: cfg.Secret, IsBase32Secret: true}

	token := string(buf)
	token = strings.Trim(token, "\r\n")
	Info.Printf("begin verify: %s.", token)
	if totp.Verify(token) {
		Info.Printf("verified by totp.")
		return true
	}
	if _, ok := cfg.EmergencySet[token]; ok {
		delete(cfg.EmergencySet, token)
		Info.Printf("verified by emergency, remember to change it.")
		return true
	}
	Info.Printf("verify failed.")
	return false
}

func TryOpenDoor(buf []byte, raddr *net.UDPAddr) {
	Info.Printf("got data from %s.\n", raddr.String())
	if !Verify(buf) {
		return
	}

	OpenCmd, err := RenderTemplate(cfg.OpenCmd, raddr)
	if err != nil {
		ErrLog.Printf("open template Error: %v.\n", err)
		return
	}

	var CloseCmd string
	if cfg.CloseCmd == "" {
		CloseCmd = ""
	} else {
		CloseCmd, err = RenderTemplate(cfg.CloseCmd, raddr)
		if err != nil {
			ErrLog.Printf("close template Error: %v.\n", err)
			return
		}
	}

	Info.Printf("open door for %s.\n", raddr.String())
	err = RunCmd(OpenCmd)
	if err != nil {
		ErrLog.Printf("open exec Error: %v.\n", err)
		return
	}

	if CloseCmd == "" {
		Info.Printf("not close cmd.")
		return
	}

	time.Sleep(time.Duration(cfg.Interval) * time.Second)

	Info.Printf("close door for %s.\n", raddr.String())
	err = RunCmd(CloseCmd)
	if err != nil {
		ErrLog.Printf("close exec Error: %v.\n", err)
		return
	}
}

func main() {
	var err error
	cfg, err = LoadConfig()
	if err != nil {
		ErrLog.Printf("load config: %v", err)
		return
	}

	laddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		ErrLog.Printf("resolve addr: %v", err)
		return
	}

	sock, err := net.ListenUDP("udp", laddr)
	if err != nil {
		ErrLog.Printf("listen: %v", err)
		return
	}
	defer sock.Close()

	Info.Println("started.")
	for {
		buf := make([]byte, 65536)
		n, raddr, err := sock.ReadFromUDP(buf)
		if err != nil {
			ErrLog.Printf("read udp: %v", err)
			continue
		}

		go TryOpenDoor(buf[:n], raddr)
	}
}
