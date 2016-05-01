package log

import (
	"fmt"
	"log/syslog"
	"os"
	"path"

	"github.com/jmhodges/clock"
)

// Logger provides a syslog logger
type Logger struct {
	SyslogWriter *syslog.Writer
	stdoutLevel  int
	clk          clock.Clock
}

const defaultPriority = syslog.LOG_INFO | syslog.LOG_LOCAL0

// NewLogger creates a new Logger
func NewLogger(network, addr string, level int, clk clock.Clock) *Logger {
	if level == 0 {
		level = 7
	}
	syslogger, err := syslog.Dial(network, addr, defaultPriority, "stapled")
	if err != nil {
		panic(err)
	}
	return &Logger{syslogger, level, clk}
}

func (log *Logger) logAtLevel(level syslog.Priority, msg string) {
	if int(level) <= log.stdoutLevel {
		fmt.Printf("%s %11s %s\n",
			log.clk.Now().Format("15:04:05"),
			path.Base(os.Args[0]),
			msg,
		)
	}

	switch level {
	case syslog.LOG_ALERT:
		log.SyslogWriter.Alert(msg)
	case syslog.LOG_CRIT:
		log.SyslogWriter.Crit(msg)
	case syslog.LOG_DEBUG:
		log.SyslogWriter.Debug(msg)
	case syslog.LOG_EMERG:
		log.SyslogWriter.Emerg(msg)
	case syslog.LOG_ERR:
		log.SyslogWriter.Err(msg)
	case syslog.LOG_INFO:
		log.SyslogWriter.Info(msg)
	case syslog.LOG_WARNING:
		log.SyslogWriter.Warning(msg)
	case syslog.LOG_NOTICE:
		log.SyslogWriter.Notice(msg)
	}
}

// Alert logs at the alert level
func (log *Logger) Alert(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_ALERT, fmt.Sprintf(msg, args...))
}

// Crit logs at the crit level
func (log *Logger) Crit(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_CRIT, fmt.Sprintf(msg, args...))
}

// Debug logs at the debug level
func (log *Logger) Debug(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_DEBUG, fmt.Sprintf(msg, args...))
}

// Emerg logs at the emergency level
func (log *Logger) Emerg(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_EMERG, fmt.Sprintf(msg, args...))
}

// Err logs at the error level
func (log *Logger) Err(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_ERR, fmt.Sprintf(msg, args...))
}

// Info logs at the info level
func (log *Logger) Info(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_INFO, fmt.Sprintf(msg, args...))
}

// Warning logs at the warning level
func (log *Logger) Warning(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_WARNING, fmt.Sprintf(msg, args...))
}

// Notice logs at the notice level
func (log *Logger) Notice(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_NOTICE, fmt.Sprintf(msg, args...))
}

// ResponderLogger wraps a Logger for the CFSSL responder interface
type ResponderLogger struct {
	Log *Logger
}

// Alert logs at the alert level
func (rl *ResponderLogger) Alert(msg string) error {
	rl.Log.Alert("[responder] " + msg)
	return nil
}

// Crit logs at the crit level
func (rl *ResponderLogger) Crit(msg string) error {
	rl.Log.Crit("[responder] " + msg)
	return nil
}

// Debug logs at the debug level
func (rl *ResponderLogger) Debug(msg string) error {
	rl.Log.Debug("[responder] " + msg)
	return nil
}

// Emerg logs at the emergency level
func (rl *ResponderLogger) Emerg(msg string) error {
	rl.Log.Emerg("[responder] " + msg)
	return nil
}

// Err logs at the error level
func (rl *ResponderLogger) Err(msg string) error {
	rl.Log.Err("[responder] " + msg)
	return nil
}

// Info logs at the info level
func (rl *ResponderLogger) Info(msg string) error {
	rl.Log.Info("[responder] " + msg)
	return nil
}

// Warning logs at the warning level
func (rl *ResponderLogger) Warning(msg string) error {
	rl.Log.Warning("[responder] " + msg)
	return nil
}

// Notice logs at the notice level
func (rl *ResponderLogger) Notice(msg string) error {
	rl.Log.Notice("[responder] " + msg)
	return nil
}
