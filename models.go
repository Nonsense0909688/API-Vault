package main

import "time"

type Secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ViewingKey struct {
	Key string `json:"key"`
}

type QueryKey struct {
	Key string `json:"key"`
}

var sessions = map[string]time.Time{}
var secrets = []Secret{}

var encryptionKey []byte
