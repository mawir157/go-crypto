package jmtcrypto

// CipherMode -
type CipherMode int

const (
	// ECB - Electronic CookBook
	ECB CipherMode = iota
	// CBC - Cipher Block Chaining
	CBC
	// PCB - Propagating Cipher Block Chaining
	PCB
	// OFB - Output FeedBack
	OFB
	// CTR - Counter
	CTR
	// CFB - Cipher FeedBack
	CFB
	// PRNGSTREAM -
	PRNGSTREAM
	// GCM - Galois/Counter Mode
	GCM
)

// BlockCipher -
type BlockCipher interface {
	blockEncrypt(plaintext []byte) []byte
	blockDecrypt(cipherText []byte) []byte
	BlockSize() int
	getKey() []byte
}

func byteStreamXOR(bs1, bs2 []byte) (bs3 []byte) {
	bs3 = make([]byte, len(bs1))
	for i := 0; i < len(bs1); i++ {
		bs3[i] = bs1[i] ^ bs2[i]
	}

	return
}

////////////////////////////////////////////////////////////////////////////////
//
// Electronic Codebook (ECB)
//

// ECBEncrypt - Electronic Codebook (ECB)
func ECBEncrypt(bc BlockCipher, msg []byte) []byte {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		eBlock := bc.blockEncrypt(msg[i : i+bc.BlockSize()])
		out = append(out, eBlock...)
	}

	return out
}

// ECBDecrypt - Electronic Codebook (ECB)
func ECBDecrypt(bc BlockCipher, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		eBlock := bc.blockDecrypt(msg[i : i+bc.BlockSize()])
		out = append(out, eBlock...)
	}

	err := validatePad(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Cipher block chaining (CBC)
//

// CBCEncrypt -
func CBCEncrypt(bc BlockCipher, iv []byte, msg []byte) []byte {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		block := byteStreamXOR(msg[i:i+bc.BlockSize()], iv)

		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock...)

		iv = eBlock
	}

	return out
}

// CBCDecrypt -
func CBCDecrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		eBlock := bc.blockDecrypt(msg[i : i+bc.BlockSize()])

		block := byteStreamXOR(eBlock, iv)
		out = append(out, block...)

		iv = msg[i : i+bc.BlockSize()]
	}

	err := validatePad(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Propagating cipher block chaining (PCBC)
//

// PCBCEncrypt -
func PCBCEncrypt(bc BlockCipher, iv []byte, msg []byte) []byte {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		block := byteStreamXOR(msg[i:i+bc.BlockSize()], iv)

		eBlock := bc.blockEncrypt(block)
		out = append(out, eBlock...)

		iv = byteStreamXOR(msg[i:i+bc.BlockSize()], eBlock)
	}

	return out
}

// PCBCDecrypt -
func PCBCDecrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		eBlock := bc.blockDecrypt(msg[i : i+bc.BlockSize()])
		block := byteStreamXOR(iv, eBlock)

		out = append(out, block...)

		iv = byteStreamXOR(msg[i:i+bc.BlockSize()], block)
	}

	err := validatePad(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Output feedback (OFB)
//

// OFBEncrypt -
func OFBEncrypt(bc BlockCipher, iv []byte, msg []byte) []byte {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		eBlock := bc.blockEncrypt(iv)

		iv = eBlock
		eBlock = byteStreamXOR(msg[i:i+bc.BlockSize()], eBlock)

		out = append(out, eBlock...)
	}

	return out
}

// OFBDecrypt -
func OFBDecrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		eBlock := bc.blockEncrypt(iv)

		iv = eBlock
		eBlock = byteStreamXOR(msg[i:i+bc.BlockSize()], eBlock)

		out = append(out, eBlock...)
	}

	err := validatePad(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Cipher feedback (CFB)
//

// CFBEncrypt -
func CFBEncrypt(bc BlockCipher, iv []byte, msg []byte) []byte {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		eBlock := bc.blockEncrypt(iv)

		eBlock = byteStreamXOR(msg[i:i+bc.BlockSize()], eBlock)

		iv = eBlock

		out = append(out, eBlock...)
	}

	return out
}

// CFBDecrypt -
func CFBDecrypt(bc BlockCipher, iv []byte, msg []byte) ([]byte, error) {
	out := []byte{}

	for i := 0; i < len(msg); i += bc.BlockSize() {
		eBlock := bc.blockEncrypt(iv)

		eBlock = byteStreamXOR(msg[i:i+bc.BlockSize()], eBlock)

		iv = msg[i : i+bc.BlockSize()]

		out = append(out, eBlock...)
	}

	err := validatePad(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Counter (CTR)
//

// CTREncrypt -
func CTREncrypt(bc BlockCipher, nonce []byte, msg []byte) []byte {
	counter := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	out := []byte{}

	// add extra byte to end so we can go process in blocks
	msgLen := len(msg)
	n := 16 - (msgLen % 16)
	pad := make([]byte, n)
	msg = append(msg, pad...)

	for i := 0; i < len(msg); i += bc.BlockSize() {
		iv := append(nonce, counter...)

		eBlock := bc.blockEncrypt(iv)
		eBlock = byteStreamXOR(msg[i:i+bc.BlockSize()], eBlock)

		out = append(out, eBlock...)

		counter = incrementCTR(counter)
	}

	return out[:msgLen]
}

// CTRDecrypt -
func CTRDecrypt(bc BlockCipher, nonce []byte, msg []byte) ([]byte, error) {
	out := CTREncrypt(bc, nonce, msg)

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
//
// Galois/Counte Mode (GCM)
//

// GCMEncrypt -
func GCMEncrypt(bc BlockCipher, nonce []byte, msg []byte, authData []byte, H []byte) ([]byte, []byte) {
	if bc.BlockSize() != 16 {
		panic("")
	}
	counter := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	eBlock0 := bc.blockEncrypt(counter)
	counter = incrementCTR(counter)
	cipherText := []byte{}
	authTag := []byte{}

	// add extra byte to end so we can go process in blocks
	msgLen := len(msg)
	n := 16 - (msgLen % 16)
	pad := make([]byte, n)
	msg = append(msg, pad...)

	rollingBlock := galoisMultiply(authData, H)

	for i := 0; i < len(msg)-bc.BlockSize(); i += bc.BlockSize() {
		eBlock := bc.blockEncrypt(counter)
		eBlock = byteStreamXOR(msg[i:i+bc.BlockSize()], eBlock)

		cipherText = byteStreamXOR(msg[i:i+bc.BlockSize()], rollingBlock)
		eBlock = galoisMultiply(eBlock, H)

		cipherText = append(cipherText, eBlock...)
		rollingBlock = eBlock

		counter = incrementCTR(counter)
	}

	// final block
	{
		blockStart, blockEnd := len(msg)-bc.BlockSize(), len(msg)
		eBlock := bc.blockEncrypt(counter)
		eBlock = byteStreamXOR(msg[blockStart:blockEnd], eBlock)
		eBlock = galoisMultiply(eBlock, H)
		final := []byte{} // WORK OUT WHT NEEDS TO HAPPEN HERE len(authData) || len(cipherText)
		eBlock = byteStreamXOR(eBlock, final)
		eBlock = galoisMultiply(eBlock, H)
		eBlock = byteStreamXOR(eBlock, eBlock0)

		cipherText = append(cipherText, eBlock...)
	}

	return cipherText[:msgLen], authTag
}

// GCMDecrypt -
func GCMDecrypt(bc BlockCipher, nonce []byte, msg []byte) ([]byte, error) {
	out := CTREncrypt(bc, nonce, msg)

	return out, nil
}

func incrementCTR(counter []byte) []byte {
	pos := 0

	counter[pos]++
	for counter[pos] == 0 {
		pos++

		if pos == len(counter) {
			break
		}

		counter[pos]++
	}

	return counter
}
