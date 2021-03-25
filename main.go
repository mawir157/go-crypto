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

// key := []byte{0x49, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x52, 0x61,
//               0x64, 0x69, 0x6f, 0x47, 0x61, 0x74, 0x75 ,0x6e}
// key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
// key := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// aes_message := [4]Word{ Word{0x54, 0x77, 0x6F, 0x20},
// 											  Word{0x4F, 0x6E, 0x65, 0x20},
// 											  Word{0x4E, 0x69, 0x6E, 0x65},
// 										    Word{0x20, 0x54, 0x77, 0x6F}, }
// aes_message := [4]Word{ Word{0x01, 0x02, 0x03, 0x04},
// 											  Word{0x05, 0x06, 0x07, 0x08},
// 											  Word{0x10, 0x12, 0x14, 0x16},
// 										    Word{0x18, 0x20, 0x22, 0x24}, }                       



// aes2 := MakeAES(aes_key)
// cipher := aes2.blockEncrypt(aes_message)
// for _, b := range cipher {
// 	fmt.Printf("%02x ", b )
// }
// fmt.Printf("\n")

// aesTest("../tests/ECBVarTxt128.rsp")
// aesTest("../tests/ECBVarTxt192.rsp")
// aesTest("../tests/ECBVarTxt256.rsp")

// fmt.Println(aes_message)
// m1 := aes2.mixColumns(aes_message[3], true)
// fmt.Println(m1)
// m2 := aes2.mixColumns(m1, false)
// fmt.Println(m2)


	textMessage :=
`It was the best of times, it was the worst of times, it was the age of wisdom,
it was the age of foolishness, it was the epoch of belief, it was the epoch of
incredulity, it was the season of Light, it was the season of Darkness, it was
the spring of hope, it was the winter of despair, we had everything before us,
we had nothing before us, we were all going direct to Heaven, we were all going
direct the other way – in short, the period was so far like the present period,
that some of its noisiest authorities insisted on its being received, for good
or for evil, in the superlative degree of comparison only.`

	public, private := generateKeyPair(2, 11)

	public.Write("mce.pub")
	private.Write("mce.pri")

	public2 := ReadPublic("mce.pub")
	private2 := ReadPrivate("mce.pri")

	cipherText := public2.Encrypt(textMessage)
	PrintHex(cipherText, true)
	
	plaintext := private2.Decrypt(cipherText)
	PrintAscii(plaintext, true)
	fmt.Println("")

	aes_key := []Word{ Word{0x54, 0x68, 0x61, 0x74}, 
										 Word{0x73, 0x20, 0x6D, 0x79},
	                   Word{0x20, 0x4B, 0x75, 0x6E}, 
	                   Word{0x67, 0x20, 0x46, 0x75}, }
	aes := MakeAES(aes_key)
	
	aesPlainText := ParseForAES(textMessage)
	aesCipherText := aes.Encrypt(aesPlainText)
	aesDecodedText := aes.Decrypt(aesCipherText)

	fmt.Println(DearseForAES(aesDecodedText))
	fmt.Println("")

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
