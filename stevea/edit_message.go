package dkim2

import (
	"io"
	"net/mail"
)

type Editor struct {
	headerCount map[string]int
	bodyReader  io.Reader
	bodyCount   int
	recipe      Recipe
}

func NewEditor(before mail.Message) *Editor {
	return nil
}

func (e *Editor) SetHeaders(name string, values []string) {}

func (e *Editor) AddHeaders(name string, values []string) {}

func (e *Editor) DeleteHeader(name string) {}

func (e *Editor) PrependBody([]string) {}

func (e *Editor) AppendBody([]string) {}
