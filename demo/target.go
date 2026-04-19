// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

// simulateMalware acts like a suspicious C2 implant beaconing
func simulateMalware() {
	fmt.Println("Malware goroutine started: beaconing every 3 seconds...")
	for {
		conn, err := net.DialTimeout("tcp", "8.8.8.8:80", 2*time.Second)
		if err == nil {
			conn.Write([]byte("PING\n"))
			conn.Close()
		}
		time.Sleep(3 * time.Second)
	}
}

// simulateKeylogger simulates rogue disk I/O
func simulateKeylogger() {
	fmt.Println("Keylogger goroutine started: writing to disk every 5 seconds...")
	for {
		f, err := os.OpenFile("/tmp/suspicious_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString("keypress\n")
			f.Close()
		}
		time.Sleep(5 * time.Second)
	}
}

func main() {
	fmt.Printf("Suspicious target process started (PID: %d)\n", os.Getpid())
	go simulateMalware()
	go simulateKeylogger()
	select {} // Block forever
}
