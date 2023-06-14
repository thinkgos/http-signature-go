package httpsign

import (
	"io"
	"strings"
)

type signatureValueParser struct {
	input string
	pos   int
	ch    byte
}

func newSignatureValueParser(input string) *signatureValueParser {
	p := &signatureValueParser{input: input, pos: -1}
	p.readChar()
	return p
}

func (p *signatureValueParser) readChar() {
	if p.pos+1 >= len(p.input) {
		p.ch = 0
	} else {
		p.ch = p.input[p.pos+1]
	}
	p.pos++
}

func (p *signatureValueParser) peekChar() byte {
	if p.pos+1 >= len(p.input) {
		return 0
	}
	return p.input[p.pos+1]
}

func (p *signatureValueParser) peekPreviousChar() byte {
	pos := p.pos - 1
	if pos < 0 || pos >= len(p.input) {
		return 0
	}
	return p.input[pos]
}

func (p *signatureValueParser) nextParam() (string, string, error) {
	if p.ch == 0 {
		return "", "", io.EOF
	}
	key := strings.Builder{}
	keyParsed := false
	val := strings.Builder{}
	isValueStartDoubleQuote := false
	for {
		switch p.ch {
		case ',', 0:
			if !keyParsed {
				return "", "", ErrMissingEqualCharacter
			}
			previousChar := p.peekPreviousChar()
			if isValueStartDoubleQuote && previousChar != '"' ||
				!isValueStartDoubleQuote && previousChar == '"' {
				return "", "", ErrMissingDoubleQuote
			}
			// FIXME: ',' '0' in double quote.
			v := val.String()
			if previousChar == '"' {
				v = v[:len(v)-1]
			}
			p.readChar()
			return key.String(), v, nil
		case '=':
			if !keyParsed {
				isValueStartDoubleQuote = p.peekChar() == '"'
				if isValueStartDoubleQuote {
					p.readChar()
				}
				keyParsed = true
			} else {
				_ = val.WriteByte(p.ch)
			}
			p.readChar()
		default:
			if !keyParsed {
				_ = key.WriteByte(p.ch)
			} else {
				_ = val.WriteByte(p.ch)
			}
			p.readChar()
		}
	}
}

func parseSignatureValue(s string) (map[string]string, error) {
	p := newSignatureValueParser(s)
	params := make(map[string]string)
	for {
		key, val, err := p.nextParam()
		if err != nil {
			if err == io.EOF {
				return params, nil
			}
			return nil, err
		}
		params[key] = val
	}
}
