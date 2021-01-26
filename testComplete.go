package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	// the filepath
	environmentFilepath := "EnvironmentData0.txt"

	shuffleFilepath := "ShuffleData0.txt"
	encryptionFilepath := "EncryptionData0.txt"
	decryptionFilepath := "DecryptionData0.txt"

	// open a file for recording the test data
	environmentFile, err := os.Create(environmentFilepath)
	check(err)                    // make sure nothing's wrong
	defer environmentFile.Close() // close the file eventually

	// open a file for recording the test data
	shuffleFile, err := os.Create(shuffleFilepath)
	check(err)                // make sure nothing's wrong
	defer shuffleFile.Close() // close the file eventually

	// open a file for recording the test data
	encryptionFile, err := os.Create(encryptionFilepath)
	check(err)                   // make sure nothing's wrong
	defer encryptionFile.Close() // close the file eventually

	// open a file for recording the test data
	decryptionFile, err := os.Create(decryptionFilepath)
	check(err)                   // make sure nothing's wrong
	defer decryptionFile.Close() // close the file eventually

	n := 20 // the number of contributors in the scheme
	t := 10 // the threshold

	// record the parameters of the test
	_, err = shuffleFile.WriteString("Environment Creation:\n")
	check(err)
	_, err = shuffleFile.WriteString("Using " + strconv.Itoa(n) + " contributors with threshold " + strconv.Itoa(t) + "\n\n")
	check(err)

	// record the parameters of the test
	_, err = encryptionFile.WriteString("Environment Creation:\n")
	check(err)
	_, err = encryptionFile.WriteString("Using " + strconv.Itoa(n) + " contributors with threshold " + strconv.Itoa(t) + "\n\n")
	check(err)

	// record the parameters of the test
	_, err = decryptionFile.WriteString("Environment Creation:\n")
	check(err)
	_, err = decryptionFile.WriteString("Using " + strconv.Itoa(n) + " contributors with threshold " + strconv.Itoa(t) + "\n\n")
	check(err)

	for i := 0; i < 10; i++ {

		newContributorCount := n - 10 + i*2
		t = newContributorCount
		// record the parameters of the test
		_, err = environmentFile.WriteString("Environment Creation:\n")
		check(err)
		_, err = environmentFile.WriteString("Using " + strconv.Itoa(newContributorCount) + " contributors with threshold " + strconv.Itoa(t) + "\n\n")
		check(err)

		for j := 0; j < 10; j++ {

			start := time.Now() // start timer

			// create the environment for the tests
			createThresholdShares(newContributorCount, t) // this is where the bulk of the time is spent: overhead for creating the system

			elapsed := time.Since(start)                                                        // end timer
			log.Printf("Environment Creation took %s", elapsed)                                 // log the time
			_, err = environmentFile.WriteString(fmt.Sprintf("%.5f", elapsed.Seconds()) + "\n") // record the time in file
			check(err)
		}
	}

	start := time.Now() // start timer

	// create the environment for the tests
	shares := createThresholdShares(n, t) // this is where the bulk of the time is spent: overhead for creating the system
	// each user's share will contain the public key
	// Since these are all the same, we choose to use the copy at index 0 arbitrarlily
	publicKey := shares[0].Public()

	elapsed := time.Since(start)                        // end timer
	log.Printf("Environment Creation took %s", elapsed) // log the time
	// _, err = file.WriteString(elapsed.String() + "\n")  // record the time in file
	// check(err)

	// check each with an exponentially increasing number of ballots
	for ballotCount := 2; ballotCount < 1050; ballotCount *= 2 {

		// state the number of ballots encrypted
		_, err = shuffleFile.WriteString("\nShuffling " + strconv.Itoa(ballotCount) + " ballots\n")
		check(err)
		// state the number of ballots encrypted
		_, err = encryptionFile.WriteString("\nEncrypting " + strconv.Itoa(ballotCount) + " ballots\n")
		check(err)
		// state the number of ballots encrypted
		_, err = decryptionFile.WriteString("\nDecrypting " + strconv.Itoa(ballotCount) + " ballots\n")
		check(err)

		for i := 0; i < 50; i++ { // do 50 tests

			start := time.Now() // start timer
			// doThresholdTest(ballotCount, n, t) // do test

			// generate messages
			messages, elGamal1, elGamal2 := generateMessageEncryptions(ballotCount, publicKey)

			elapsed := time.Since(start)                                                       // end timer
			log.Printf("Encryption took %s", elapsed)                                          // log the time
			_, err = encryptionFile.WriteString(fmt.Sprintf("%.5f", elapsed.Seconds()) + "\n") // record the time in file
			check(err)
			start = time.Now() // restart timer

			// shuffle the messages
			elGamal1, elGamal2 = shuffleAndCheck(publicKey, elGamal1, elGamal2)

			elapsed = time.Since(start)                                                     // end timer
			log.Printf("Shuffle took %s", elapsed)                                          // log the time
			_, err = shuffleFile.WriteString(fmt.Sprintf("%.5f", elapsed.Seconds()) + "\n") // record the time in file
			check(err)
			start = time.Now() // restart timer

			// decrypt the messages, using the distributed shares
			decryptedMessages := decryptMessages(elGamal1, elGamal2, shares, t, n)

			fmt.Println("Byte Length:")
			fmt.Println(suite.Point().EmbedLen())
			fmt.Println("Original Values:")
			for _, item := range messages {
				value, err := item.Data()
				check(err)
				fmt.Println(string(value))
			}
			fmt.Println("Decrypted Values:")
			for _, item := range decryptedMessages {
				value, err := item.Data()
				check(err)
				fmt.Println(string(value))
			}

			// assures all decryptions are correct
			//checkDecryption(messages, decryptedMessages)

			elapsed = time.Since(start)                                                        // end timer
			log.Printf("Decryption took %s", elapsed)                                          // log the time
			_, err = decryptionFile.WriteString(fmt.Sprintf("%.5f", elapsed.Seconds()) + "\n") // record the time in file
			check(err)
		}
	}

}
