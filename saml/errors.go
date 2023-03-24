package saml

import "errors"

var (
	ErrEmptyMetadataURL           = errors.New("must provide non null metadata URL")
	ErrInvalidKey                 = errors.New("invalid key type, must be (*rsa.PrivateKey)")
	ErrDuplicateIDPProvider       = errors.New("duplicate provider")
	ErrProviderRegistrationFailed = errors.New("could not configure provider")
)
