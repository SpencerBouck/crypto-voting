package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"time"

	"go.dedis.ch/kyber"
)

// hyper-parameters
var messagePartitions = 8
var randomnessLength = 16

func main2() {
	// the filepath
	filepath := "longMessageTestData.txt"

	// open a file for recording the test data
	file, err := os.Create(filepath)
	check(err)         // make sure nothing's wrong
	defer file.Close() // close the file eventually

	n := 5 // the number of contributors in the scheme
	t := 5 // the threshold

	// record the parameters of the test
	_, err = file.WriteString("Environment Creation:\n")
	check(err)
	_, err = file.WriteString("Using " + strconv.Itoa(n) + " cotruibutors with threshold " + strconv.Itoa(t) + "\n\n")
	check(err)

	start := time.Now() // start timer

	// create the environment for the tests
	shares := createThresholdShares(n, t) // this is where the bulk of the time is spent: overhead for creating the system
	// each user's share will contain the public key
	// Since these are all the same, we choose to use the copy at index 0 arbitrarlily
	publicKey := shares[0].Public()

	elapsed := time.Since(start)                        // end timer
	log.Printf("Environment Creation took %s", elapsed) // log the time
	_, err = file.WriteString(elapsed.String() + "\n")  // record the time in file
	check(err)

	// check each with an exponentially increasing number of ballots
	for ballotCount := 50; ballotCount < 100; ballotCount *= 2 {

		// state the number of ballots encrypted
		_, err = file.WriteString("\nEncrypting " + strconv.Itoa(ballotCount) + " ballots\n")
		check(err)

		for i := 0; i < 1; i++ { // do 1 tests

			start := time.Now() // start timer
			// doThresholdTest(ballotCount, n, t) // do test

			// generate messages
			messages, elGamal1, elGamal2 := generateLongMessageEncryptions(ballotCount, publicKey)

			elapsed := time.Since(start)                       // end timer
			log.Printf("Encryption took %s", elapsed)          // log the time
			_, err = file.WriteString(elapsed.String() + "\n") // record the time in file
			check(err)
			start = time.Now() // restart timer

			// shuffle the messages
			elGamal1, elGamal2 = shuffleAndCheck(publicKey, elGamal1, elGamal2)

			elapsed = time.Since(start)                        // end timer
			log.Printf("Shuffle took %s", elapsed)             // log the time
			_, err = file.WriteString(elapsed.String() + "\n") // record the time in file
			check(err)
			start = time.Now() // restart timer

			// decrypt the messages, using the distributed shares
			decryptedMessages := decryptMessages(elGamal1, elGamal2, shares, t, n)

			/*
				fmt.Println("Byte Length:")
				fmt.Println(suite.Point().EmbedLen())
				fmt.Println("Original Values:")
				for _, item := range messages {
					fmt.Println(item)
				}
				fmt.Println("Decrypted Values:")
				for _, item := range decryptedMessages {
					value, err := item.Data()
					check(err)
					fmt.Println(string(value))
				}
			*/
			fmt.Println("Compiled Values:")
			for _, item := range compileMessages(decryptedMessages) {
				fmt.Println(item)
			}

			// assures all decryptions are correct
			checkDecryption(messages, decryptedMessages)

			elapsed = time.Since(start)                        // end timer
			log.Printf("Decryption took %s", elapsed)          // log the time
			_, err = file.WriteString(elapsed.String() + "\n") // record the time in file
			check(err)
		}
	}
}

func encryptLongMessage(data []byte, h kyber.Point) (messagePortions, elGamal1, elGamal2 []kyber.Point) {

	// create a blank byte array to XOR with randomness
	blankData := make([]byte, randomnessLength)
	for i := 0; i < randomnessLength; i++ {
		blankData[i] = 0 // this doesn't matter, as it will be XORed with random bytes
	}

	messagePortions = make([]kyber.Point, messagePartitions)
	elGamal1 = make([]kyber.Point, messagePartitions)
	elGamal2 = make([]kyber.Point, messagePartitions)

	meaningfulDataLength := suite.Point().EmbedLen() - randomnessLength - 1 // the length of meaningful data: length available - randomness length - 1 postional byte
	remainingData := data                                                   // the data left in the message
	var embeddedMessage kyber.Point                                         // the point to hold this message portion
	randomBytes := make([]byte, randomnessLength)                           // the array to hold the randomness, to be reused in each message chunk
	suite.RandomStream().XORKeyStream(randomBytes, blankData)               // initialize the randomness in the buffer

	// split the message into parts, encrypt each
	for i := range messagePortions {

		buffer := make([]byte, suite.Point().EmbedLen()) // a buffer to hold the message portion

		// for k := range buffer {
		// 	buffer[k] = 0 // initialize buffer to nil
		// }

		copy(buffer[0:randomnessLength], randomBytes) // transfer the randomness to the buffer

		// the Byte to determine message portion order
		buffer[randomnessLength] = byte(i) // index of this message portion

		if len(remainingData) >= meaningfulDataLength { // the buffer will be full
			copy(buffer[randomnessLength+1:len(buffer)], remainingData[0:meaningfulDataLength]) // copy as much data to the buffer as will fit
			remainingData = remainingData[meaningfulDataLength:len(remainingData)]              // remove coppied data from the list of data to copy
		} else { // the buffer will not be full
			copy(buffer[randomnessLength+1:len(buffer)], remainingData[0:len(remainingData)]) // copy all remaining data to the buffer
			remainingData = remainingData[0:0]                                                // remove all data, there is none left to copy
		}

		embeddedMessage = suite.Point().Embed(buffer, suite.RandomStream()) // embed the message portion
		messagePortions[i] = embeddedMessage                                // record the message portion embedding
		elGamal1[i], elGamal2[i] = encryptMessage(embeddedMessage, h)       // encrypt the message portion
		//fmt.Printf(string(buffer))
	}

	return // messagePortions, elGamal1, elGamal2
}

// generates long messages
func generateLongMessageEncryptions(n int, h kyber.Point) (messages, elGamal1, elGamal2 []kyber.Point) {

	// these three slices are given at size 0, as we will append to them later on
	messages = make([]kyber.Point, 0) // the el gamal messages
	elGamal1 = make([]kyber.Point, 0) // the el gamal pairs
	elGamal2 = make([]kyber.Point, 0) // the el gamal pairs

	// declare the messages to be used
	defaultLongMessages := make([]string, 0) // the default, sample messages
	defaultLongMessages = append(defaultLongMessages, "Hello. My name is BOB. I vote for Smith.")
	defaultLongMessages = append(defaultLongMessages, "Bonjour. My name is ALBERT. I vote for QUEEN.")
	defaultLongMessages = append(defaultLongMessages, "Hi. My name is ALSO BOB. I vote for NIL.")
	defaultLongMessages = append(defaultLongMessages, "HMMM... I pass.")
	defaultLongMessages = append(defaultLongMessages, "This is an example message. As you can see, these messages can be quite long indeed!")

	// initialize the elGamal pairs
	// // pick random messages
	// pick meaningful messages
	// and encrypt them with the threshold public key
	for i := 0; i < n; i++ {
		// messages[i] = suite.Point().Pick(suite.RandomStream())
		var data []byte
		if i < len(defaultLongMessages) { // use a manually created message
			data = []byte(defaultLongMessages[i])
		} else { // use a generated sample message
			data = []byte("This is Sample Long Message #" + strconv.Itoa(i))
		}

		messagesToAdd, elGamal1ToAdd, elGamal2ToAdd := encryptLongMessage(data, h) // encrypt the long message
		messages = append(messages, messagesToAdd...)                              // add messages
		elGamal1 = append(elGamal1, elGamal1ToAdd...)                              // add elGamal1
		elGamal2 = append(elGamal2, elGamal2ToAdd...)                              // add elGamal2

	}

	return // messages, elGamal1, elGamal2

}

// SortableBytesList is a wrapper for a double array of bytes, used to sort
type SortableBytesList [][]byte

// simple minimum function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// functions required for sorting
func (a SortableBytesList) Len() int      { return len(a) }
func (a SortableBytesList) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a SortableBytesList) Less(i, j int) bool {
	for k := 0; k < min(len(a[i]), len(a[j])); k++ { // loop through the byte array to see the first byte that differs
		if a[i][k] != a[j][k] { // if this byte differs...
			return a[i][k] < a[j][k] // it is either greater or less than the other byte
		}
	}
	return len(a[i]) < len(a[j]) // no bytes differed
}

// helper function to tell whether two arrays of bytes have the same data
func isDataEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false // the length of the slices to not match
	}
	for i := range a { // the arrays have the same length, so we can index over either
		if a[i] != b[i] { // this byte is different
			return false
		}
	}
	// everything matched
	return true
}

// combines all messages into individual long messages
func compileMessages(decryptedMessages []kyber.Point) (completeMessages []string) {
	messageChunks := make([][]byte, len(decryptedMessages)) // make room for the decrypted messages

	// find the decoding of all decrypted messages
	for i := range decryptedMessages {
		data, err := decryptedMessages[i].Data()   // retrieve the data from the point
		messageChunks[i] = make([]byte, len(data)) // prepare room for the data to be stored
		copy(messageChunks[i], data)               // copy the data to the message chunks array
		check(err)                                 // no error
	}
	// all data has been retrieved

	// we don't know exactly how many messages there will be by the end,
	// so we allocate space dynamically
	completeMessages = make([]string, 0)

	// fmt.Print("Message chunks! ")
	// fmt.Println(messageChunks)
	sort.Sort(SortableBytesList(messageChunks)) // sort the bytes
	fmt.Println("We've sorted successfully")
	// all similarly prefixed messages will be organized together, in increasing order of positional index
	// eg, 6C31-0-I vote for
	// and 6C31-1- Tom Smith
	// will come one after the other

	// Edge cases:
	// messages have more than messagePartitions pieces:
	// if the messages have the same content, merge them
	// if there's a conflict, ignore the message
	// messages have less than messagePartitions pieces:
	// fit them together by index
	//
	currentPrefix := make([]byte, 0) // the current prefix: nothing
	currentIndex := byte(0)

	for i := range messageChunks {
		prefix := messageChunks[i][0:randomnessLength]                       // the random prefix/nonce of the message portion
		index := messageChunks[i][randomnessLength]                          // the position of the message chunk in the whole message
		data := messageChunks[i][randomnessLength+1 : len(messageChunks[i])] // the actual data of the message

		if isDataEqual(currentPrefix, prefix) { // this is the same prefix as the privious message

			if currentIndex == index { // duplicate message portion, ignore it
				continue // we skip recording this message
				// NOTE: alternative implementations can record this duplicate message
				// it is cryptographically assured that the contents of these message portions are identical
				// UNLESS both parts are submitted by the same user
				// eg. F3A8-1-I will vote for...
				// and F3A8-1-I dont vote for...
			} else { // the index is unique (and, because the list is sorted, greater than the previous)
				// could check here to make sure index is one greater than the previous
				// but this is largely unnecessary

				currentIndex = index // update index
				// add the new data onto the existing message
				updatedMessage := completeMessages[len(completeMessages)-1] + string(data)
				completeMessages[len(completeMessages)-1] = updatedMessage
			}
		} else { // different prefix
			currentPrefix = prefix                                  // update prefix
			currentIndex = index                                    // update index
			newMessage := string(data)                              // allocate space for a string
			completeMessages = append(completeMessages, newMessage) // add the message
		}

	}

	return // completeMessages
}
