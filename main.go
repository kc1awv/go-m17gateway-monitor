/*
Copyright (C) 2024 Steve Miller KC1AWV

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var debug bool

func init() {
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
}

// main is the entry point of the program
func main() {
	flag.Parse()

	if debug {
		// Enable logging to stdout for debugging
		log.SetOutput(os.Stdout)
	} else {
		// Disable logging
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			log.Fatalf("failed to open %s: %v", os.DevNull, err)
		}
		defer devNull.Close()
		log.SetOutput(devNull)
	}

	// Create a new client and start listening for packets
	client, err := NewClient("lo") // "lo" is the loopback interface on Linux
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	go client.listen()

	// Wait for SIGINT or SIGTERM to shutdown the client
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down client...")
	client.cancel()
}
