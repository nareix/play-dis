package main

import (
	"fmt"
	"path/filepath"
)

func main() {
	a, _ := filepath.Abs("sss")
	fmt.Println(a)
}
