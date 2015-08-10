package logger_test

import (
	"io"
	"io/ioutil"
	"log"
	"os"

	logger "ibm-security-innovation/libsecurity-go/logger"
)

// This example show the following:
// - Discard Trace messages
// - Write Info messages to stdout
// - Write Warning to stdout and log file
// - Write Error to stderr and log file
func Example_logger() {
	fileName := "log-file.txt"
	os.Remove(fileName)
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("Failed to open log file", fileName, ":", err)
	}

	multiW := io.MultiWriter(file, os.Stdout)
	multiE := io.MultiWriter(file, os.Stderr)
	logger.Init(ioutil.Discard, os.Stdout, multiW, multiE)

	logger.Trace.Println("Example: I have something standard to say")
	logger.Info.Println("Example: Special Information")
	logger.Warning.Println("Example: There is something you need to know about")
	logger.Error.Println("Example: Something has failed")
}
