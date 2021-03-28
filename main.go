package main

import "flag"
import "fmt"
import "log"
import "os"
import "runtime/pprof"
import "runtime"

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")

func main() {

	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	textMessage :=
`It was the best of times, it was the worst of times, it was the age of wisdom,
it was the age of foolishness, it was the epoch of belief, it was the epoch of
incredulity, it was the season of Light, it was the season of Darkness, it was
the spring of hope, it was the winter of despair, we had everything before us,
we had nothing before us, we were all going direct to Heaven, we were all going
direct the other way – in short, the period was so far like the present period,
that some of its noisiest authorities insisted on its being received, for good
or for evil, in the superlative degree of comparison only.`


	//////////////////////////////////////////////////////////////////////////////
	//
	// McEliese
	//
	public, private := generateKeyPair(2, 11)

	public.Write("mce.pub")
	private.Write("mce.pri")

	public2 := ReadPublic("mce.pub")
	private2 := ReadPrivate("mce.pri")

	cipherText := public2.Encrypt(textMessage)
	// PrintHex(cipherText, true)
	
	plaintext := private2.Decrypt(cipherText)
	PrintAscii(plaintext, true)
	fmt.Println("")


	//////////////////////////////////////////////////////////////////////////////
	//
	// ECB w/ AES
	//
	aes_key := randomBlock(8)
	aes := MakeAES(aes_key)
	
	aesPlainText   := ParseForAES(textMessage)
	aesCipherText  := ECBEncrypt(aes, aesPlainText)
	aesDecodedText := ECBDecrypt(aes, aesCipherText)

	fmt.Println(DearseForAES(aesDecodedText))
	fmt.Println("")
	//////////////////////////////////////////////////////////////////////////////
	//
	// CBC w/ AES
	//
	aes_key = randomBlock(8)
	aes = MakeAES(aes_key)

	var iv [4]Word
	temp := randomBlock(4)
	copy(iv[:], temp)

	aesCipherText  = CBCEncrypt(aes, iv, aesPlainText)
	aesDecodedText = CBCDecrypt(aes, iv, aesCipherText)

	fmt.Println(DearseForAES(aesDecodedText))
	fmt.Println("")
	//////////////////////////////////////////////////////////////////////////////
	//
	// PCB w/ AES
	//
	aes_key = randomBlock(8)
	aes = MakeAES(aes_key)
	temp = randomBlock(4)
	copy(iv[:], temp)

	aesCipherText  = PCBCEncrypt(aes, iv, aesPlainText)
	aesDecodedText = PCBCDecrypt(aes, iv, aesCipherText)

	fmt.Println(DearseForAES(aesDecodedText))
	fmt.Println("")
	//////////////////////////////////////////////////////////////////////////////
	//
	// OFB w/ AES
	//
	aes_key = randomBlock(8)
	aes = MakeAES(aes_key)
	temp = randomBlock(4)
	copy(iv[:], temp)

	aesCipherText  = OFBEncrypt(aes, iv, aesPlainText)
	aesDecodedText = OFBDecrypt(aes, iv, aesCipherText)

	fmt.Println(DearseForAES(aesDecodedText))
	fmt.Println("")
	//////////////////////////////////////////////////////////////////////////////
	//
	// CFB w/ AES
	//
	aes_key = randomBlock(8)
	aes = MakeAES(aes_key)
	temp = randomBlock(4)
	copy(iv[:], temp)

	aesCipherText  = CFBEncrypt(aes, iv, aesPlainText)
	aesDecodedText = CFBDecrypt(aes, iv, aesCipherText)

	fmt.Println(DearseForAES(aesDecodedText))
	fmt.Println("")

	// ECB
	aesECBTest("../tests/ECBVarSbox128.rsp")
	aesECBTest("../tests/ECBVarSbox192.rsp")
	aesECBTest("../tests/ECBVarSbox256.rsp")

	aesECBTest("../tests/ECBVarKey128.rsp")
	aesECBTest("../tests/ECBVarKey192.rsp")
	aesECBTest("../tests/ECBVarKey256.rsp")

	aesECBTest("../tests/ECBVarTxt128.rsp")
	aesECBTest("../tests/ECBVarTxt192.rsp")
	aesECBTest("../tests/ECBVarTxt256.rsp")

	// CBC
	aesCBCTest("../tests/CBCVarSbox128.rsp")
	aesCBCTest("../tests/CBCVarSbox192.rsp")
	aesCBCTest("../tests/CBCVarSbox256.rsp")

	aesCBCTest("../tests/CBCVarKey128.rsp")
	aesCBCTest("../tests/CBCVarKey192.rsp")
	aesCBCTest("../tests/CBCVarKey256.rsp")

	aesCBCTest("../tests/CBCVarTxt128.rsp")
	aesCBCTest("../tests/CBCVarTxt192.rsp")
	aesCBCTest("../tests/CBCVarTxt256.rsp")	

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}

 	return
}
