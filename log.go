package stapled

import (
	"fmt"
	"log/syslog"
	"os"
	"path"

	"github.com/jmhodges/clock"
)

type Logger struct {
	SyslogWriter *syslog.Writer
	stdoutLevel  int
	clk          clock.Clock
}

const defaultPriority = syslog.LOG_INFO | syslog.LOG_LOCAL0

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

func (log *Logger) Alert(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_ALERT, fmt.Sprintf(msg, args...))
}

func (log *Logger) Crit(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_CRIT, fmt.Sprintf(msg, args...))
}

func (log *Logger) Debug(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_DEBUG, fmt.Sprintf(msg, args...))
}

func (log *Logger) Emerg(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_EMERG, fmt.Sprintf(msg, args...))
}

func (log *Logger) Err(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_ERR, fmt.Sprintf(msg, args...))
}

func (log *Logger) Info(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_INFO, fmt.Sprintf(msg, args...))
}

func (log *Logger) Warning(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_WARNING, fmt.Sprintf(msg, args...))
}

func (log *Logger) Notice(msg string, args ...interface{}) {
	log.logAtLevel(syslog.LOG_NOTICE, fmt.Sprintf(msg, args...))
}
