// Package logger : The logger package contains the implementation of log handling.
package logger

import (
	"io"
	"io/ioutil"
	"log"
	"os"
)

var (
	// Trace : write trace information to the logger
	Trace *log.Logger
	// Info : write info and trace information to the logger
	Info *log.Logger
	// Warning : write warnings, info and trace information to the logger
	Warning *log.Logger
	// Error : write errors, warnings, info and trace information to the logger
	Error *log.Logger
)

func init() {
	Init(ioutil.Discard, ioutil.Discard, os.Stdout, os.Stderr)
}

// Init : initialize the logger
func Init(traceHandle io.Writer, infoHandle io.Writer, warningHandle io.Writer, errorHandle io.Writer) {
	Trace = log.New(traceHandle, "TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle, "INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(warningHandle, "WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle, "ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

// type UtilLogger {
// 	_trace   *log.Logger
// 	_info    *log.Logger
// 	_warning *log.Logger
// 	_error   *log.Logger
// }

// func (logger UtilLogger *) New(traceHandle io.Writer, infoHandle io.Writer, warningHandle io.Writer, errorHandle io.Writer) {
// 	logger._trace = log.New(traceHandle, "TRACE: ",
// 		log.Ldate|log.Ltime|log.Lshortfile)

// 	logger._info = log.New(infoHandle, "INFO: ",
// 		log.Ldate|log.Ltime|log.Lshortfile)

// 	logger._warning = log.New(warningHandle, "WARNING: ",
// 		log.Ldate|log.Ltime|log.Lshortfile)

// 	logger._error = log.New(errorHandle, "ERROR: ",
// 		log.Ldate|log.Ltime|log.Lshortfile)

// }

// func (logger UtilLogger *) Info(msg) {
// 	logger._info.Println(msg)
// }
