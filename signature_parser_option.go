package httpsign

type ParserOption func(*Parser)

func WithMinimumRequiredHeaders(headers []string) ParserOption {
	return func(p *Parser) {
		p.minimumRequiredHeaders = headers
	}
}

func WithValidators(vs ...Validator) ParserOption {
	return func(p *Parser) {
		p.validators = vs
	}
}

func WithExtractor(e Extractor) ParserOption {
	return func(p *Parser) {
		p.extractor = e
	}
}

func WithKeystone(ks Keystone) ParserOption {
	return func(p *Parser) {
		p.keystone = ks
	}
}

func WithSigningMethods(alg string, f func() SigningMethod) ParserOption {
	return func(p *Parser) {
		p.RegisterSigningMethod(alg, f)
	}
}
