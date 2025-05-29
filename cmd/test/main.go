package main

import (
	"log"
	"os"
	"path/filepath"

	"../../test"
)

func main() {
	// 确保在正确的目录中运行
	if err := os.Chdir(filepath.Dir(os.Args[0])); err != nil {
		log.Fatalf("Failed to change directory: %v", err)
	}

	// 运行测试
	if err := test.RunTest(); err != nil {
		log.Fatalf("Test failed: %v", err)
	}
}
