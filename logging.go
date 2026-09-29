package main

import "log"

func logEvent(event string, details string) {
	log.Printf("[API-VAULT] %s %s", event, details)
}
