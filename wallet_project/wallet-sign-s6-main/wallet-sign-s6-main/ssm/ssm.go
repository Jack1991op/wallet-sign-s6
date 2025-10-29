package ssm

type Signer interface {
	CreateKeyPair() (privateKey string, publicKey string, compressPubKey string, err error)
	SignMessage(privKey string, msg string) (signature string, err error)
	VerifySignature(pubKey string, msgHash string, signature string) (bool, error)
}
