package main

import (
	"os"
	"os/exec"
)

func main() {
	exec.Command("hi")
	os.Create("hi")
}
