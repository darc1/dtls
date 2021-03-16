package dtls

// https://tools.ietf.org/html/rfc5246#section-7.4
type handshakeType uint8

const (
	handshakeTypeHelloRequest       handshakeType = 0
	handshakeTypeClientHello        handshakeType = 1
	handshakeTypeServerHello        handshakeType = 2
	handshakeTypeHelloVerifyRequest handshakeType = 3
	handshakeTypeCertificate        handshakeType = 11
	handshakeTypeServerKeyExchange  handshakeType = 12
	handshakeTypeCertificateRequest handshakeType = 13
	handshakeTypeServerHelloDone    handshakeType = 14
	handshakeTypeCertificateVerify  handshakeType = 15
	handshakeTypeClientKeyExchange  handshakeType = 16
	handshakeTypeFinished           handshakeType = 20

	// msg_len for Handshake messages assumes an extra 12 bytes for
	// sequence, fragment and version information
	handshakeMessageHeaderLength = 12
)

type HandshakeMessage interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error

	handshakeType() handshakeType
}

func (h handshakeType) String() string {
	switch h {
	case handshakeTypeHelloRequest:
		return "HelloRequest"
	case handshakeTypeClientHello:
		return "ClientHello"
	case handshakeTypeServerHello:
		return "ServerHello"
	case handshakeTypeHelloVerifyRequest:
		return "HelloVerifyRequest"
	case handshakeTypeCertificate:
		return "TypeCertificate"
	case handshakeTypeServerKeyExchange:
		return "ServerKeyExchange"
	case handshakeTypeCertificateRequest:
		return "CertificateRequest"
	case handshakeTypeServerHelloDone:
		return "ServerHelloDone"
	case handshakeTypeCertificateVerify:
		return "CertificateVerify"
	case handshakeTypeClientKeyExchange:
		return "ClientKeyExchange"
	case handshakeTypeFinished:
		return "Finished"
	}
	return ""
}

// The Handshake protocol is responsible for selecting a cipher spec and
// generating a master secret, which together comprise the primary
// cryptographic parameters associated with a secure session.  The
// Handshake protocol can also optionally authenticate parties who have
// certificates signed by a trusted certificate authority.
// https://tools.ietf.org/html/rfc5246#section-7.3
type Handshake struct {
	handshakeHeader  handshakeHeader
	HandshakeMessage HandshakeMessage
}

func (h Handshake) contentType() contentType {
	return contentTypeHandshake
}

func (h *Handshake) Marshal() ([]byte, error) {
	if h.HandshakeMessage == nil {
		return nil, errHandshakeMessageUnset
	} else if h.handshakeHeader.fragmentOffset != 0 {
		return nil, errUnableToMarshalFragmented
	}

	msg, err := h.HandshakeMessage.Marshal()
	if err != nil {
		return nil, err
	}

	h.handshakeHeader.length = uint32(len(msg))
	h.handshakeHeader.fragmentLength = h.handshakeHeader.length
	h.handshakeHeader.handshakeType = h.HandshakeMessage.handshakeType()
	header, err := h.handshakeHeader.Marshal()
	if err != nil {
		return nil, err
	}

	return append(header, msg...), nil
}

func (h *Handshake) Unmarshal(data []byte) error {
	if err := h.handshakeHeader.Unmarshal(data); err != nil {
		return err
	}

	reportedLen := bigEndianUint24(data[1:])
	if uint32(len(data)-handshakeMessageHeaderLength) != reportedLen {
		return errLengthMismatch
	} else if reportedLen != h.handshakeHeader.fragmentLength {
		return errLengthMismatch
	}

	switch handshakeType(data[0]) {
	case handshakeTypeHelloRequest:
		return errNotImplemented
	case handshakeTypeClientHello:
		h.HandshakeMessage = &HandshakeMessageClientHello{}
	case handshakeTypeHelloVerifyRequest:
		h.HandshakeMessage = &handshakeMessageHelloVerifyRequest{}
	case handshakeTypeServerHello:
		h.HandshakeMessage = &handshakeMessageServerHello{}
	case handshakeTypeCertificate:
		h.HandshakeMessage = &handshakeMessageCertificate{}
	case handshakeTypeServerKeyExchange:
		h.HandshakeMessage = &handshakeMessageServerKeyExchange{}
	case handshakeTypeCertificateRequest:
		h.HandshakeMessage = &handshakeMessageCertificateRequest{}
	case handshakeTypeServerHelloDone:
		h.HandshakeMessage = &handshakeMessageServerHelloDone{}
	case handshakeTypeClientKeyExchange:
		h.HandshakeMessage = &handshakeMessageClientKeyExchange{}
	case handshakeTypeFinished:
		h.HandshakeMessage = &handshakeMessageFinished{}
	case handshakeTypeCertificateVerify:
		h.HandshakeMessage = &handshakeMessageCertificateVerify{}
	default:
		return errNotImplemented
	}
	return h.HandshakeMessage.Unmarshal(data[handshakeMessageHeaderLength:])
}
