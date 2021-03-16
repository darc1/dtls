package dtls

import (
	"encoding/binary"
)

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type ExtensionValue uint16

const (
	extensionServerNameValue                   ExtensionValue = 0
	extensionSupportedEllipticCurvesValue      ExtensionValue = 10
	extensionSupportedPointFormatsValue        ExtensionValue = 11
	extensionSupportedSignatureAlgorithmsValue ExtensionValue = 13
	extensionUseSRTPValue                      ExtensionValue = 14
	extensionUseExtendedMasterSecretValue      ExtensionValue = 23
)

type Extension interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error

	ExtensionValue() ExtensionValue
}

func decodeExtensions(buf []byte) ([]Extension, error) {
	if len(buf) < 2 {
		return nil, errBufferTooSmall
	}
	declaredLen := binary.BigEndian.Uint16(buf)
	if len(buf)-2 != int(declaredLen) {
		return nil, errLengthMismatch
	}

	extensions := []Extension{}
	unmarshalAndAppend := func(data []byte, e Extension) error {
		err := e.Unmarshal(data)
		if err != nil {
			return err
		}
		extensions = append(extensions, e)
		return nil
	}

	for offset := 2; offset < len(buf); {
		if len(buf) < (offset + 2) {
			return nil, errBufferTooSmall
		}
		var err error
		switch ExtensionValue(binary.BigEndian.Uint16(buf[offset:])) {
		case extensionServerNameValue:
			err = unmarshalAndAppend(buf[offset:], &ExtensionServerName{})
		case extensionSupportedEllipticCurvesValue:
			err = unmarshalAndAppend(buf[offset:], &extensionSupportedEllipticCurves{})
		case extensionUseSRTPValue:
			err = unmarshalAndAppend(buf[offset:], &extensionUseSRTP{})
		case extensionUseExtendedMasterSecretValue:
			err = unmarshalAndAppend(buf[offset:], &extensionUseExtendedMasterSecret{})
		default:
		}
		if err != nil {
			return nil, err
		}
		if len(buf) < (offset + 4) {
			return nil, errBufferTooSmall
		}
		extensionLength := binary.BigEndian.Uint16(buf[offset+2:])
		offset += (4 + int(extensionLength))
	}
	return extensions, nil
}

func encodeExtensions(e []Extension) ([]byte, error) {
	extensions := []byte{}
	for _, e := range e {
		raw, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, raw...)
	}
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(extensions)))
	return append(out, extensions...), nil
}
