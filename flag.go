package main

import (
	"errors"
	"strings"
	"time"
)

type mapFlags map[string]string

func (i *mapFlags) String() string {
	return "mapFlags"
}

func (i *mapFlags) Set(value string) error {
	slice := strings.SplitN(value, "=", 2)
	if len(slice) != 2 {
		return errors.New("the value must include = ")
	}
	if len(*i) == 0 {
		*i = map[string]string{}
	}
	(*i)[slice[0]] = slice[1]
	return nil
}

func newMapFlags(val map[string]string, p *map[string]string) *mapFlags {
	*p = val
	return (*mapFlags)(p)
}

type timeFlag time.Time

func (i *timeFlag) String() string {
	return "timeFlag"
}

func (i *timeFlag) Set(value string) error {
	t, err := time.Parse("2006-01-02T15:04:05", value)
	if err != nil {
		return err
	}
	*i = timeFlag(t)
	return nil
}

func newTimeFlag(val time.Time, p *time.Time) *timeFlag {
	*p = val
	return (*timeFlag)(p)
}
