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
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CAUTION: DO NOT PROTECT SYSTEM FROM BLIND GUESS.
// attacker could use that as DOS attack.
// they can spoof their source IP address.

var (
	errConfig = errors.New("config file wrong")

	Info   = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warn   = log.New(os.Stdout, "WARN: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
)

type Config struct {
	Secret       string
	SecretBin    []byte `json:"-"`
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
		Warn.Printf("config file should't read or write by others.")
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

	cfg.SecretBin, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cfg.Secret)
	if err != nil {
		return
	}

	if len(cfg.Emergency) == 0 {
		Warn.Printf("run without emergency, may be dangerous.")
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

func TryOpenDoor(raddr *net.UDPAddr) {
	OpenCmd, err := RenderTemplate(cfg.OpenCmd, raddr)
	if err != nil {
		ErrLog.Printf("open template Error: %v.\n", err)
		return
	}

	Info.Printf("open door for %s.\n", raddr.String())
	err = RunCmd(OpenCmd)
	if err != nil {
		ErrLog.Printf("open exec Error: %v.\n", err)
		return
	}

	if cfg.CloseCmd == "" {
		Info.Printf("no close cmd.")
		return
	}

	time.Sleep(time.Duration(cfg.Interval) * time.Second)

	CloseCmd, err := RenderTemplate(cfg.CloseCmd, raddr)
	if err != nil {
		ErrLog.Printf("close template Error: %v.\n", err)
		return
	}

	Info.Printf("close door for %s.\n", raddr.String())
	err = RunCmd(CloseCmd)
	if err != nil {
		ErrLog.Printf("close exec Error: %v.\n", err)
		return
	}
	return
}

func Calotp(secret []byte, counter uint64) string {
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, counter)

	h := hmac.New(sha1.New, secret)
	h.Write(message)
	hash := h.Sum(nil)

	offset := int(hash[len(hash)-1] & 0xf)
	bignum := (binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff)
	return fmt.Sprintf("%06d", bignum%1000000)
}

func VerifyToken(secret []byte, token string) bool {
	t := uint64(time.Now().Unix())/30 - 1
	var i uint64
	for i = 0; i <= 2; i++ {
		if Calotp(secret, t+i) == token {
			return true
		}
	}
	return false
}

func Verify(buf []byte) bool {
	// 先检查原始长度，考虑可能有换行符，但太长就没必要继续了
	if len(buf) < 6 || len(buf) > 10 {
		Info.Printf("verify failed: raw data length %d out of reasonable range.", len(buf))
		return false
	}

	token := string(buf)
	token = strings.Trim(token, "\r\n")

	// 检查trim后长度是否在6-8位之间
	if len(token) < 6 || len(token) > 8 {
		Info.Printf("verify failed: token length %d is not in range [6,8].", len(token))
		return false
	}

	// 使用strconv检查是否全部为数字
	if _, err := strconv.Atoi(token); err != nil {
		Info.Printf("verify failed: token is not a valid number.")
		return false
	}

	Info.Printf("begin verify: %s.", token)
	if VerifyToken(cfg.SecretBin, token) {
		Info.Printf("verified by totp.")
		return true
	}

	if _, ok := cfg.EmergencySet[token]; ok {
		delete(cfg.EmergencySet, token)
		Warn.Printf("verified by emergency, don't forget to rotate it.")
		return true
	}
	Info.Printf("verify failed.")
	return false
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
	buf := make([]byte, 65536)
	for {
		n, raddr, err := sock.ReadFromUDP(buf)
		if err != nil {
			ErrLog.Printf("read udp: %v", err)
			continue
		}

		Info.Printf("got data from %s.\n", raddr.String())
		if !Verify(buf[:n]) {
			continue
		}

		go TryOpenDoor(raddr)
	}
}
