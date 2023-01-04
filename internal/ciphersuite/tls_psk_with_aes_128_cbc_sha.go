package ciphersuite

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"sync/atomic"

	"github.com/neobilitly/dtls/v2/pkg/crypto/ciphersuite"
	"github.com/neobilitly/dtls/v2/pkg/crypto/clientcertificate"
	"github.com/neobilitly/dtls/v2/pkg/crypto/prf"
	"github.com/neobilitly/dtls/v2/pkg/protocol/recordlayer"
)

// TLSPskWithAes128CbcSha implements the TLS_PSK_WITH_AES_128_CBC_SHA256 CipherSuite
type TLSPskWithAes128CbcSha struct {
	cbc atomic.Value // *cryptoCBC
}

// CertificateType returns what type of certificate this CipherSuite exchanges
func (c *TLSPskWithAes128CbcSha) CertificateType() clientcertificate.Type {
	return clientcertificate.Type(0)
}

// KeyExchangeAlgorithm controls what key exchange algorithm is using during the handshake
func (c *TLSPskWithAes128CbcSha) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmPsk
}

// ECC uses Elliptic Curve Cryptography
func (c *TLSPskWithAes128CbcSha) ECC() bool {
	return false
}

// ID returns the ID of the CipherSuite
func (c *TLSPskWithAes128CbcSha) ID() ID {
	return TLS_PSK_WITH_AES_128_CBC_SHA
}

func (c *TLSPskWithAes128CbcSha) String() string {
	return "TLS_PSK_WITH_AES_128_CBC_SHA256"
}

// HashFunc returns the hashing func for this CipherSuite
func (c *TLSPskWithAes128CbcSha) HashFunc() func() hash.Hash {
	return sha1.New
}

// AuthenticationType controls what authentication method is using during the handshake
func (c *TLSPskWithAes128CbcSha) AuthenticationType() AuthenticationType {
	return AuthenticationTypePreSharedKey
}

// IsInitialized returns if the CipherSuite has keying material and can
// encrypt/decrypt packets
func (c *TLSPskWithAes128CbcSha) IsInitialized() bool {
	return c.cbc.Load() != nil
}

// Init initializes the internal Cipher with keying material
func (c *TLSPskWithAes128CbcSha) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 32
		prfKeyLen = 16
		prfIvLen  = 16
	)

	keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc())
	if err != nil {
		return err
	}

	var cbc *ciphersuite.CBC
	if isClient {
		cbc, err = ciphersuite.NewCBC(
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			c.HashFunc(),
		)
	} else {
		cbc, err = ciphersuite.NewCBC(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			c.HashFunc(),
		)
	}
	c.cbc.Store(cbc)

	return err
}

// Encrypt encrypts a single TLS RecordLayer
func (c *TLSPskWithAes128CbcSha) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.cbc.Load().(*ciphersuite.CBC)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Encrypt(pkt, raw)
}

// Decrypt decrypts a single TLS RecordLayer
func (c *TLSPskWithAes128CbcSha) Decrypt(raw []byte) ([]byte, error) {
	cipherSuite, ok := c.cbc.Load().(*ciphersuite.CBC)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Decrypt(raw)
}
