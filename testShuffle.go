package main

import (
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/proof"
	"go.dedis.ch/kyber/shuffle"
)

// preform a shuffle test
func doShuffleTest(listLength int) {

	a := suite.Scalar().Pick(suite.RandomStream()) // the private key
	h := suite.Point().Mul(a, nil)                 // the public key

	messages, elGamal1, elGamal2 := generateMessageEncryptions(listLength, h) // generate messages
	newElGamal1, newElGamal2 := shuffleAndCheck(h, elGamal1, elGamal2)        // shuffle them
	decryptedMessages := decryptAll(newElGamal1, newElGamal2, a)              // decrypt the shuffled messages
	checkDecryption(messages, decryptedMessages)                              // verify correct decryption
}

// shuffles and verifies the shuffle of elGamal encrypted points
// takes in the public key and two list which together represent a list of el Gamal pairs
// NOTE: this is the only function we need from this file for the complete scheme
func shuffleAndCheck(h kyber.Point, elGamal1, elGamal2 []kyber.Point) (shuffledElGamal1, shuffledElGamal2 []kyber.Point) {

	shuffledElGamal1, shuffledElGamal2, prover := shuffle.Shuffle(suite, suite.Point().Base(), h, elGamal1[:], elGamal2[:], suite.RandomStream())

	// Prove the shuffle
	// This certifies that the shuffle was performed correctly,
	// and prevents cheating
	prf, err := proof.HashProve(suite, "PairShuffle", prover)
	if err != nil {
		panic("Shuffle proof failed: " + err.Error())
	}

	// Verify the proof
	// each user could do this to the proof provided of the shuffle
	// This will catch cheating done by the shuffler
	verifier := shuffle.Verifier(suite, suite.Point().Base(), h, elGamal1[:], elGamal2[:], shuffledElGamal1, shuffledElGamal2)
	err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
	if err != nil {
		panic("Shuffle verify failed: " + err.Error())
	}

	return // shuffledElGamal1, shuffledElGamal2
}

// decrypts an El Gamal message
// uses the secret key in the decryption process
// this would be infeasable in a distributed environment,
// but is useful for testing
func decryptMessage(elGamal1, elGamal2 kyber.Point, secret kyber.Scalar) (message kyber.Point) {

	toReverseElGamal := suite.Point().Mul(secret, elGamal1) // (g^y)^x == g^(xy)
	message = suite.Point().Sub(elGamal2, toReverseElGamal) // M == Mg^(xy) / g^(xy)

	return // message
}

// decrypts all El Gamal messages
func decryptAll(elGamal1, elGamal2 []kyber.Point, secret kyber.Scalar) (decrpyedMessages []kyber.Point) {
	decrpyedMessages = make([]kyber.Point, len(elGamal1)) // allocate space for the decrypted el gamal messages
	for i := range elGamal1 {
		decrpyedMessages[i] = decryptMessage(elGamal1[i], elGamal2[i], secret) // decrypt each messsage
	}
	return // decryptedMessages
}
