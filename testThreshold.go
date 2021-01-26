package main

import (
	"sort"
	"strconv"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/share"
	vss "go.dedis.ch/kyber/share/dkg/pedersen"
	"go.dedis.ch/kyber/suites"
)

var suite = suites.MustFind("ed25519") // Use the edwards25519-curve
//var suite = suites.MustFind("P256") // Use the NIST P-256 elliptic curve

// helper function to quickly make sure no error exists
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// from dedis github
// generates a public/private key pair randomly
func genPair() (kyber.Scalar, kyber.Point) {
	sc := suite.Scalar().Pick(suite.RandomStream())
	return sc, suite.Point().Mul(sc, nil)
}

// preform a shuffle test
// reading this function will provide a high-level understanding of the scheme used
func doThresholdTest(listLength, contributorCount, threshold int) {

	// create the environment
	// each user gets a share, which contains:
	// 1) a portion of the secret key
	// 2) the public key
	// for the cryptosystem
	shares := createThresholdShares(contributorCount, threshold)

	// each user's share will contain the public key
	// Since these are all the same, we choose to use the copy at index 0 arbitrarlily
	publicKey := shares[0].Public()

	// generate messages
	messages, elGamal1, elGamal2 := generateMessageEncryptions(listLength, publicKey)

	// --------------------------------------------------------- //
	//                     Decryption Begins                     //
	// --------------------------------------------------------  //

	// decrypt the messages, using the distributed shares
	decryptedMessages := decryptMessages(elGamal1, elGamal2, shares, threshold, contributorCount)

	// assures all decryptions are correct
	checkDecryption(messages, decryptedMessages)
}

// helper function to decrypt a list of messages
// takes in the encrypted messages, the shares of the private threshold key,
// and the parameters of the threshold cryptosystem
// returns the list of decrypted messages
func decryptMessages(elGamal1, elGamal2 []kyber.Point, shares []*vss.DistKeyShare, threshold, contributorCount int) (decryptedMessages []kyber.Point) {
	// allocate space for the decrypted el gamal messages
	decryptedMessages = make([]kyber.Point, len(elGamal1))

	// decrypt each of the messages
	for i := range elGamal1 { // for each message

		shadows := make([]*share.PubShare, len(shares)) // allocate space for the partial decryptions
		for j := range shares {
			// each contributor could do this themselves
			shadows[j] = extractShadow(elGamal1[i], elGamal2[i], shares[j])
			// the shadow extracted is a partial decryption of the given message
			// each user has their own shadow for the message
		}

		// to decrypt the message, we take the encrypted message,
		// the parameters of the threshold system,
		// and the list of shadows from each of the users
		decryptedMessages[i] = decryptMessageSecretless(elGamal1[i], elGamal2[i], shadows, threshold, contributorCount)
	}

	return // decryptedMessages
}

// does the preliminary step required for using a threshold cryptosystem
// returns the shares that belong to the users
// Each share has a private part, which is unique to that user,
// and a public part, which is the public key for the threshold cryptosystem
// (and is the same for all users)
func createThresholdShares(contributorCount, threshold int) (shares []*vss.DistKeyShare) {

	// the users create their own dkgs using the public keys of the other users
	// each dkg is all that is needed for the threshold system
	dkgs := generate(contributorCount, threshold)

	fullShare(dkgs) // communicate between the dkgs

	// collect shares
	// each user should have their own share
	// creating a share fulfills the purpose of the dkg
	shares = make([]*vss.DistKeyShare, 0, len(dkgs)) // allocate space for the shares
	for _, shareholder := range dkgs {               // for each generator
		if shareholder.Certified() { // make sure it's certified
			newShare, err := shareholder.DistKeyShare() // get the share
			check(err)
			shares = append(shares, newShare) // add it
		}
	}
	return // shares
}

// adapted from dedis github
// makes public/private key pairs, and makes a dgk for each private key
// publicly executable, as each dkg created only uses one private key
// and the public keys
// follows "A Threshold Cryptosystem Without a Trusted Party"
func generate(n, t int) (dkgs []*vss.DistKeyGenerator) {
	// Each public/private keypair represents the identity of a user
	// in a distributed application, these keypairs will be created by each user independently
	partPubs := make([]kyber.Point, n) // allocate space for public key parts
	partSec := make([]kyber.Scalar, n) // allocate space for private key parts
	for i := 0; i < n; i++ {           // for n users
		sec, pub := genPair()
		partPubs[i] = pub // the public key for the user
		partSec[i] = sec  // the private key for the user
	}

	// allocate space for the key generators
	dkgs = make([]*vss.DistKeyGenerator, n)

	// each user...
	for i := 0; i < n; i++ {

		// creates a key generator
		// uses one user's private key
		// the dkg created is now linked to that user
		dkg, err := vss.NewDistKeyGenerator(suite, partSec[i], partPubs, t)
		check(err)
		dkgs[i] = dkg
	}
	// after this point, the keypair is no longer used
	// each dkg now effectively represents a user's identity

	return dkgs
}

// encrypts an El Gamal message
func encryptMessage(message, pubKey kyber.Point) (elGamal1, elGamal2 kyber.Point) {
	tempScalar := suite.Scalar().Pick(suite.RandomStream())
	elGamal1 = suite.Point().Mul(tempScalar, nil)
	elGamal2 = suite.Point().Mul(tempScalar, pubKey)
	elGamal2.Add(elGamal2, message)

	return
}

// decrypts an El Gamal message
// given the encrypted message, the list of shadows,
// and the parameters for the threshold system
// the decryption is "secretless" because the secret exponent is never revealed
// follows the scheme outlined in Sections 2.2 and 3.1 of "Threshold Cryptosystems" by Desmedt and Frankel
func decryptMessageSecretless(elGamal1, elGamal2 kyber.Point, shadows []*share.PubShare, t, n int) (message kyber.Point) {

	// With a message M and secret x, encrypted as the tuple (g^y, Mg^(xy))
	// recovers the committment g^(xy)
	// this acts as a key to decrypt the original message
	// by dividing Mg^(xy) by g^(xy)

	key, err := share.RecoverCommit(suite, shadows, t, n) // recover g^(xy), essentially by multiplying its factors together
	check(err)                                            // no error
	message = suite.Point().Sub(elGamal2, key)            // M = Mg^(xy) / g^(xy)

	return // message
}

// Follows the scheme outlined in Section 2.1 of "Threshold Cryptosystems" by Desmedt and Frankel
// extracts the tuple g^kV_i, i
// given a public el gamal encrpyed message,
// and a share (kept private),
// returns the corresponding shadow
// this shadow essentially is a factor of the committment used
// in the second half of an El Gamal encrypted message
func extractShadow(elGamal1, elGamal2 kyber.Point, distShare *vss.DistKeyShare) (shadow *share.PubShare) {

	priv := distShare.PriShare()                 // private share x_i
	value := suite.Point().Mul(priv.V, elGamal1) // g^(y*x_i)
	index := priv.I                              // record the index of the user to keep the shadws ordered
	shadow = &share.PubShare{I: index, V: value} // struct for recovering commit later
	return                                       // shadow
}

// communicates the required information for the key generators to function
func fullShare(dkgs []*vss.DistKeyGenerator) {

	// This function shares all of the information between all dkgs
	// the outline for the communication steps were provided on the dedis github,
	// following an error-resistant implementation of the scheme described in
	// "A Threshold Cryptosystem without a Trusted Party"

	// There are three phases for the communication:
	// 1) Deals
	// Each user conveys information about itself to all others
	// 2) Responses
	// Each user makes sure that all of the deals it recieves are consistent
	// If a given deal is compliant, the response indicate that it was accepted
	// otherwise, the response will indicate that a justification for the deal is needed
	// 3) Justifications
	// This phase gives users the chance to justify their deal
	// This can occur when either party has made a mistake
	// Usually, no justification is needed, and none is given

	// allocate space for the responses
	resps := make([]*vss.Response, 0, len(dkgs)*len(dkgs))

	// here, the dkgs know only the public keys of the other users
	// more information is needed in order to create a share of the public threshold key

	// deal all shares
	for _, generator := range dkgs {
		deals, err := generator.Deals() // each dkg has a deal for each other user
		check(err)

		for j, deal := range deals { // for each deal
			processor := dkgs[j]

			//process the deal
			response, err := processor.ProcessDeal(deal)
			check(err) // no error
			// record the response to the deal
			// index of response is contributorCount * sender index + reciever index
			resps = append(resps, response)
			// each response is

		}
	}
	// all deals dealt

	// distribute responses
	for _, response := range resps {
		for i, dkg := range dkgs { // everone can process every response

			// don't justify to yourself
			if uint32(i) == response.Response.Index {
				continue
			}

			// handle response to the deal, justify deal to responder
			justification, err := dkg.ProcessResponse(response)
			check(err) // no error

			// process justification
			// This can be done directly after the response is given,
			// independently of other responses

			// justification will be nil if there is nothing to justify
			// this is normally the case
			if justification != nil {
				sender := dkgs[response.Response.Index]
				err = sender.ProcessJustification(justification)
				check(err) // make sure the justification is valid
			}
		}
	}
	// all responses distributed
}

// SortablePointList is a wrapper for []]kyber.Point
// this allows for these lists to be sorted
type SortablePointList []kyber.Point

// functions required for sorting
func (a SortablePointList) Len() int           { return len(a) }
func (a SortablePointList) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortablePointList) Less(i, j int) bool { return a[i].String() < a[j].String() }

// helper function, compares two lists of points
// checks if the decryptions of messages matches the original messages
func checkDecryption(messages, decryptedMessages []kyber.Point) {

	// message lengths match up
	if len(messages) != len(decryptedMessages) {
		panic("Decrypted messages do not match up with messages! (different len)")
	}

	// sort the lists, as one may have been shuffled
	sort.Sort(SortablePointList(messages))
	sort.Sort(SortablePointList(decryptedMessages))

	// check each pair of messages
	for i := range messages {
		// fmt.Println("Message:", messages[i])
		// fmt.Println("Decrypted Message:", decryptedMessages[i])
		// fmt.Println()
		if messages[i].Equal(decryptedMessages[i]) == false {
			panic("Message incorrectly decrypted!") // messages do not match
		}
	}
}

// helper function, generates a list of messages alongside their encryptions
// generates n messages and their encryptions with a given public key h
// encryptions are done in El Gamal,
// where each index represents an encrypted message
// in pseudocode: encrypt(message[i]) == (elGamal1[i], elGamal2[i])
func generateMessageEncryptions(n int, h kyber.Point) (messages, elGamal1, elGamal2 []kyber.Point) {

	messages = make([]kyber.Point, n) // the el gamal messages
	elGamal1 = make([]kyber.Point, n) // the el gamal pairs
	elGamal2 = make([]kyber.Point, n) // the el gamal pairs

	// initialize the elGamal pairs
	// // pick random messages
	// pick meaningful messages
	// and encrypt them with the threshold public key
	for i := range messages {
		// messages[i] = suite.Point().Pick(suite.RandomStream())
		data := []byte("Sample Message " + strconv.Itoa(i))
		messages[i] = suite.Point().Embed(data, suite.RandomStream())
		elGamal1[i], elGamal2[i] = encryptMessage(messages[i], h) // can use any share's public key
	}

	return // messages, elGamal1, elGamal2
}
