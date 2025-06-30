package main

import (
	"log/slog"
	"strconv"
	"time"
)

func parseConfigTime(input string) *time.Duration {
	if input == "" {
		return nil
	}

	var timeUnit time.Duration

	unit := input[len(input)-1:]
	switch unit {
	case "m":
		timeUnit = time.Minute
	case "s":
		timeUnit = time.Second
	default:
		slog.Error("Invalid time unit in CaDbRefresh", "value", input, "unit", unit)
		return nil
	}

	value, err := strconv.Atoi(input[:len(input)-1])
	if err != nil {
		slog.Error("Invalid time value in CaDbRefresh", "value", input, "error", err)
		return nil
	}

	td := (time.Duration(value) * timeUnit)

	return &td
}
