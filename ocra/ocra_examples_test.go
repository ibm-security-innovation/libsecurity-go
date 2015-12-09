package ocra_test

import (
	"fmt"
	"strconv"

	"github.com/ibm-security-innovation/libsecurity-go/ocra"
)

const (
	mutualOcraSuite = "OCRA-1:HOTP-SHA256-8:C-QA08"
	mutualPassword  = "123456"
	OKStr           = "OK"
	NOKStr          = "NOK"

	failFmt = "Generate OCRA fail: error: %v"
)

var (
	channel     = make(chan string)
	doneChannel = make(chan string)
)

// Example of Generate an ocra code using the minimal required parameters: ocra key.
// The OCRA suite is the default one and the question is generated automatically
func GenerateOCRA() {
	key := "3132333435363738393031323334353637383930"

	otp, question, err := ocra.GenerateOCRA(key)
	if err != nil {
		fmt.Printf("Error while generaing OCRA with key: %v and random question: %v, otp: %v\n", key, []byte(question), otp)
	} else {
		fmt.Printf("The OCRA for: with key: %v and random question is OK\n", key)
	}
}

// Execute the oneWayChallengeResponse client:
// 1. Wait for the ocra suite defined by the server (in this example)
//    and the server's randomly generated question
// 2. Send to the server the calculated ocra value (using the ocra suite and the server's question)
// 3. Send the server's approval to the "done channel"
func oneWayChallengeResponseClient(key string) {
	oneWayOcraSuite := <-channel
	question := <-channel

	otp, err := ocra.GenerateOCRAAdvance(oneWayOcraSuite, key, "", question, "", "", "")
	if err != nil {
		doneChannel <- fmt.Sprintf(failFmt, err)
	}
	fmt.Printf("Client otp: %v, Ocra suite: %v, Question: '%v'\n", otp, oneWayOcraSuite, question)
	channel <- otp
	ok := <-channel
	doneChannel <- ok
}

// In this example, The oneWayOcraSuite is defined by the server and sent to the client
// 1. Send the ocra suite and the "random" question to the client
// 2. Comapre the expected calculated ocra value with the one recived from the client
// 3. Based on the result of the comparison, send either an 'OK' or a 'NOK' message to the client
func oneWayChallengeResponseServer(key string) {
	oneWayOcraSuite := "OCRA-1:HOTP-SHA1-6:QA08"
	question := "abcd1234"

	channel <- oneWayOcraSuite
	channel <- question

	refOtp, err := ocra.GenerateOCRAAdvance(oneWayOcraSuite, key, "", question, "", "", "")
	if err != nil {
		doneChannel <- fmt.Sprintf(failFmt, err)
	}
	otp := <-channel
	if otp == refOtp {
		channel <- OKStr
	} else {
		channel <- NOKStr
	}
}

// Execute the mutulChallengeResponse client: In this example the ocra suite is predefined both for the client and the server
// 1. Send the client's randomly generated question to the server
// 2. Get from the server the calculated ocra value based on both the client's question and the server's question
// 3. Comapre the ocra value calculated in the previous step with the one recived from the server
// 4. If the values are equal: the server is authenticated
//    4.1. Send the calculated ocra value to the server
//    4.2. If an OK message is received from the server - increase the 'ocra used' counter (to prevent replay attacks)
//    4.3. Send the message recived from the server (OK or NOK) to the "done channel"

func mutualChallengeResponseClient(key string, counter string) {
	QC := "Client 1234"
	channel <- QC

	RS := <-channel
	QS := <-channel

	sOtp, err := ocra.GenerateOCRAAdvance(mutualOcraSuite, key, counter, QC+QS, mutualPassword, "", "")
	if err != nil {
		doneChannel <- fmt.Sprintf(failFmt, err)
	}

	RC, err := ocra.GenerateOCRAAdvance(mutualOcraSuite, key, counter, QS+QC, mutualPassword, "", "")
	if err != nil {
		doneChannel <- fmt.Sprintf(failFmt, err)
	}

	if RS == sOtp {
		channel <- RC
	} else {
		channel <- "0"
	}
	fmt.Printf("Client/Server otp: (%v,%v), Ocra suite: %v, Client/Server questions: ('%v','%v'), counter: %v, password: %v\n",
		RC, RS, mutualOcraSuite, QC, QS, counter, mutualPassword)
	ok := <-channel
	if ok == OKStr {
		val, _ := strconv.Atoi(counter)
		counter = fmt.Sprintf("%06d", val+1)
	}
	doneChannel <- ok
}

// Execute the mutulChallengeResponse server: in this example the ocra suite is predefined both for the client and the server
// 1. Wait for the client's randomly generated question
// 2. Send to the client both the calculated ocra value (based on the ocra suite and client's + server's questions) and the server's question
// 3. Get from the client the calculated ocra value based on the client's and server's questions
// 4. Calculate the expected ocra value based on both the client's and the server's questions
// 5. Comapre the calculated ocra value with the one recived from the client
// 6. If the values are equal: the client is authenticated
//    6.1. Send an OK message to the client
//    6.2. Increase the 'ocra used' counter (to prevent replay attacks)
// 7. Else (the values are not equal) send a NOK message to the client
func mutualChallengeResponseServer(key string, counter string) {
	QS := "Server 9879"

	QC := <-channel

	RS, err := ocra.GenerateOCRAAdvance(mutualOcraSuite, key, counter, QC+QS, mutualPassword, "", "")
	if err != nil {
		doneChannel <- fmt.Sprintf(failFmt, err)
	}

	channel <- RS
	channel <- QS

	RC := <-channel
	cOtp, err := ocra.GenerateOCRAAdvance(mutualOcraSuite, key, counter, QS+QC, mutualPassword, "", "")
	if err != nil {
		doneChannel <- fmt.Sprintf(failFmt, err)
	}

	if RC == cOtp {
		channel <- OKStr
		val, _ := strconv.Atoi(counter)
		counter = fmt.Sprintf("%06d", val+1)
	} else {
		channel <- NOKStr
	}
}

// Mutual Challenge-Response example.
// Mutual challenge-response is a variation of the one-way challenge-response
// procedure where both the client and server mutually authenticate each other.
// To use this algorithm, the client will first send a random client-challenge message
// to the server. The server computes the server-response and
// sends it back to the client along with a server-challenge message.
// The client will first verify the server-response to make sure that
// it is talking to a valid server. It will then compute the client-
// response and send it back to the server for authentication. The server
// verifies the client-response in order to complete the two-way authentication	process.
// In this mode there are two computations: client-response and server-response.
// There are two separate challenge questions, generated by	both parties.
func ShowOcraMutualWayChallengeResponse() {
	key := "3132333435363738393031323334353637383930"
	counter := "00010"

	go mutualChallengeResponseClient(key, counter)
	go mutualChallengeResponseServer(key, counter)
	fmt.Println("mutualChallengeResponse status:", <-doneChannel)
}

// Example of One-Way Challenge-Response.
// A challenge-response is a security mechanism in which the verifier
// presents a question (challenge) to the prover, who must provide a
// valid answer (response) to be authenticated.
// To use this algorithm for a one-way challenge-response, the verifier
// will communicate a challenge value (typically randomly generated) to
// the prover. The prover will use the recieved challenge in the computation as
// described above. The prover then communicates the response back to the
// verifier for authentication
func ShowOcraOneWayChallengeResponse() {
	key := "3132333435363738393031323334353637383930"

	go oneWayChallengeResponseClient(key)
	go oneWayChallengeResponseServer(key)
	fmt.Println("oneWayChallengeResponse status:", <-doneChannel)
}

func Example_ocra() {
	GenerateOCRA()
	ShowOcraMutualWayChallengeResponse()
	ShowOcraOneWayChallengeResponse()
}
