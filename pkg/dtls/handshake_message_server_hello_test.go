package dtls

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHandshakeMessageServerHello(t *testing.T) {
	rawServerHello := []byte{
		0xfe, 0xfd, 0x21, 0x63, 0x32, 0x21, 0x81, 0x0e, 0x98, 0x6c,
		0x85, 0x3d, 0xa4, 0x39, 0xaf, 0x5f, 0xd6, 0x5c, 0xcc, 0x20,
		0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e,
		0xcf, 0x63, 0x84, 0x28, 0x00, 0xc0, 0x2b, 0x00, 0x00, 0x00,
	}
	parsedServerHello := &handshakeMessageServerHello{
		version: protocolVersion{0xFE, 0xFD},
		random: handshakeRandom{
			time.Unix(560149025, 0),
			[28]byte{0x81, 0x0e, 0x98, 0x6c, 0x85, 0x3d, 0xa4, 0x39, 0xaf, 0x5f, 0xd6, 0x5c, 0xcc, 0x20, 0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e, 0xcf, 0x63, 0x84, 0x28},
		},
		cipherSuite:       cipherSuites[TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
		compressionMethod: compressionMethods[compressionMethodNull],
		extensions:        []extension{},
	}

	c := &handshakeMessageServerHello{}
	if err := c.unmarshal(rawServerHello); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(c, parsedServerHello) {
		t.Errorf("handshakeMessageServerHello unmarshal: got %#v, want %#v", c, parsedServerHello)
	}

	raw, err := c.marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawServerHello) {
		assert.Equal(t, raw, rawServerHello)
		t.Errorf("handshakeMessageServerHello marshal: got %#v, want %#v", raw, rawServerHello)
	}
}