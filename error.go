package doh

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

var (
	ErrNoAnswer = errors.New("no answer")
)

type dohError struct {
	InnerError error
	Doamin     string
	Type       dns.Type
}

func (e *dohError) Unwrap() error {
	return ErrNoAnswer
}

func (e *dohError) Error() string {
	return fmt.Sprintf("DoH: query domain %s on type %s: %s", e.Doamin, e.Type.String(), e.InnerError.Error())
}
