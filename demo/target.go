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
		conn, err := net.DialTimeout("tcp", "127.0.0.1:19999", 2*time.Second)
		if err == nil {
			if _, err := conn.Write([]byte("ping\n")); err != nil {
				fmt.Printf("Error writing to connection: %v\n", err)
			}
			conn.Close()
		}
		time.Sleep(3 * time.Second)
	}
}

// simulateKeylogger simulates rogue disk I/O
func simulateKeylogger(logPath string) {
	fmt.Println("Keylogger goroutine started: writing to disk every 5 seconds...")
	for {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
		if err == nil {
			if _, err := f.WriteString("keypress\n"); err != nil {
				fmt.Printf("Error writing to file: %v\n", err)
			}
			f.Close()
		}
		time.Sleep(5 * time.Second)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: target <demo-log-file>")
		os.Exit(1)
	}
	fmt.Printf("Suspicious target process started (PID: %d)\n", os.Getpid())
	go simulateMalware()
	go simulateKeylogger(os.Args[1])
	select {} // Block forever
}
