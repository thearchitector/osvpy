package main

// Stateless logging avoids SCALIBR cmdlogger's mutable error bookkeeping.
type discardLogger struct{}

func (discardLogger) Errorf(string, ...any) {}
func (discardLogger) Warnf(string, ...any)  {}
func (discardLogger) Infof(string, ...any)  {}
func (discardLogger) Debugf(string, ...any) {}
func (discardLogger) Error(...any)          {}
func (discardLogger) Warn(...any)           {}
func (discardLogger) Info(...any)           {}
func (discardLogger) Debug(...any)          {}
