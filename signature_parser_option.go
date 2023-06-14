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

func WithValidatorCreated(v ValidatorTimestamp) ParserOption {
	return func(p *Parser) {
		p.validatorCreated = v
	}
}

func WithValidatorExpires(v ValidatorTimestamp) ParserOption {
	return func(p *Parser) {
		p.validatorExpires = v
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
