package main

type config struct {
	Key map[string]key
}

type key struct {
	Secret string
}
