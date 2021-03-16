package dtls

import (
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const ExtensionServerNameTypeDNSHostName = 0

type ExtensionServerName struct {
	ServerName string
}

func (e ExtensionServerName) ExtensionValue() ExtensionValue {
	return extensionServerNameValue
}

func (e *ExtensionServerName) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(e.ExtensionValue()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(ExtensionServerNameTypeDNSHostName)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(e.ServerName))
			})
		})
	})
	return b.Bytes()
}

func (e *ExtensionServerName) Unmarshal(data []byte) error {
	s := cryptobyte.String(data)
	var extension uint16
	s.ReadUint16(&extension)
	if ExtensionValue(extension) != e.ExtensionValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	s.ReadUint16LengthPrefixed(&extData)

	var nameList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
		return errInvalidSNIFormat
	}
	for !nameList.Empty() {
		var nameType uint8
		var serverName cryptobyte.String
		if !nameList.ReadUint8(&nameType) ||
			!nameList.ReadUint16LengthPrefixed(&serverName) ||
			serverName.Empty() {
			return errInvalidSNIFormat
		}
		if nameType != ExtensionServerNameTypeDNSHostName {
			continue
		}
		if len(e.ServerName) != 0 {
			// Multiple names of the same name_type are prohibited.
			return errInvalidSNIFormat
		}
		e.ServerName = string(serverName)
		// An SNI value may not include a trailing dot.
		if strings.HasSuffix(e.ServerName, ".") {
			return errInvalidSNIFormat
		}
	}
	return nil
}
