package main

func main() {
	textMessage :=
`It was the best of times, it was the worst of times, it was the age of wisdom,
it was the age of foolishness, it was the epoch of belief, it was the epoch of
incredulity, it was the season of Light, it was the season of Darkness, it was
the spring of hope, it was the winter of despair, we had everything before us,
we had nothing before us, we were all going direct to Heaven, we were all going
direct the other way – in short, the period was so far like the present period,
that some of its noisiest authorities insisted on its being received, for good
or for evil, in the superlative degree of comparison only.`

	public, private := generateKeyPair(2, 12)
	public.Write("mce.pub")
	private.Write("mce.pri")

	// public2 := ReadPublic("mce.pub")
	cipherText := public.Encrypt(textMessage)
	PrintHex(cipherText, true)
	// cipherText := public2.Encrypt(textMessage)
	
	plaintext := private.Decrypt(cipherText)
	PrintAscii(plaintext, true)

 	return
}
