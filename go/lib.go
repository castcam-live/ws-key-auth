package wskeyauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
)

type TypeData struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// <- CLIENT_ID
// -> CHALLENGE
// <- CHALLENGE_RESPONSE
// And then either:
//   -> SIGNATURE_MATCHES
//   or
//   -> SIGNATURE_MISMATCH

// A client ID will be of the format
//
// WebCrypto-raw.EC.<named curve>$<base64 encoded public key>

func ErrInvalidClientID() error {
	return errors.New("invalid client ID")
}

func ErrFailedToReadRandomNumbers() error {
	return errors.New("failed to read random numbers")
}

func parseClientID(clientID string) (*ecdsa.PublicKey, error) {
	s := strings.Split(clientID, "$")
	if len(s) != 2 {
		return nil, fmt.Errorf("expected client ID to have exactly one $. The client ID: %s", clientID)
	}

	if s[0] != "WebCrypto-raw.EC.P-256" {
		return nil, fmt.Errorf("expected client ID to have prefix WebCrypto-raw.EC.P-256. The client ID: %s", clientID)
	}

	buff, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}

	if len(buff) != 65 {
		return nil, errors.New("expected P-256 key of ID to be 65 bytes long")
	}

	if buff[0] != 4 {
		return nil, errors.New("expected P-256 key of ID to have 0x04 as the first byte")
	}

	x := &big.Int{}
	y := &big.Int{}

	x.SetBytes(buff[1:33])
	y.SetBytes(buff[33:])

	return &ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: elliptic.P256(),
	}, nil
}

const challengeByteLength = 128

// It will be safe to assume that any error coming from this function is a client
func getChallengePayload() (b []byte, err error) {
	b = make([]byte, challengeByteLength)
	n, err := rand.Read(b)
	if err != nil {
		return []byte{}, err
	}
	if n < challengeByteLength {
		return []byte{}, ErrFailedToReadRandomNumbers()
	}
	return b, nil
}

// Handshake will perform the handshake with the client and return true if the
// client is authenticated and false if not. If an error is returned, the
// connection should be closed.
func Handshake(conn *websocket.Conn) (bool, error) {
	var td TypeData
	err := conn.ReadJSON(&td)
	if err != nil {
		return false, err
	}

	if td.Type != "CLIENT_ID" {
		conn.WriteJSON(map[string]string{
			"type": "CLIENT_ERROR",
			"data": "Expected a CLIENT_ID event, but got " + td.Type + "",
		})
		return false, nil
	}

	var clientID string
	err = json.Unmarshal(td.Data, &clientID)
	if err != nil {
		conn.WriteJSON(map[string]any{
			"type": "CLIENT_ERROR",
			"data": map[string]string{
				"message": "Failed to parse CLIENT_ID",
				"error":   err.Error(),
			},
		})
		return false, err
	}

	pubKey, err := parseClientID(clientID)

	if err != nil {
		conn.WriteJSON(map[string]any{
			"type": "CLIENT_ERROR",
			"data": map[string]string{
				"message": "Failed to parse CLIENT_ID",
				"error":   err.Error(),
			},
		})
		return false, err
	}

	if pubKey == nil {
		conn.WriteJSON(map[string]any{
			"type": "CLIENT_ERROR",
			"data": map[string]string{
				"message": "Failed to parse CLIENT_ID",
			},
		})
		return false, nil
	}

	payload, err := getChallengePayload()
	if err != nil {
		return false, err
	}

	challenge := base64.StdEncoding.EncodeToString(payload)

	if err != nil {
		conn.WriteJSON(map[string]any{
			"type": "SERVER_ERROR",
			"data": map[string]string{
				"message": "Failed to generate challenge",
				"error":   err.Error(),
			},
		})
		return false, err
	}

	conn.WriteJSON(map[string]string{
		"type": "CHALLENGE",
		"data": challenge,
	})

	err = conn.ReadJSON(&td)
	if err != nil {
		conn.WriteJSON(map[string]any{
			"type": "SERVER_ERROR",
			"data": map[string]string{
				"message": "Failed to read CHALLENGE_RESPONSE",
				"error":   err.Error(),
			},
		})
		return false, err
	}

	if td.Type != "CHALLENGE_RESPONSE" {
		conn.WriteJSON(map[string]string{
			"type": "CLIENT_ERROR",
			"data": "Expected a CHALLENGE_RESPONSE event, but got " + td.Type + "",
		})
		return false, nil
	}

	var challengeResponse string
	err = json.Unmarshal(td.Data, &challengeResponse)
	if err != nil {
		conn.WriteJSON(map[string]any{
			"type": "CLIENT_ERROR",
			"data": map[string]string{
				"message": "Failed to parse CHALLENGE_RESPONSE",
				"error":   err.Error(),
			},
		})
		return false, err
	}

	decodedChallengeResponse, err := base64.StdEncoding.DecodeString(challengeResponse)
	if err != nil {
		conn.WriteJSON(map[string]any{
			"type": "CLIENT_ERROR",
			"data": map[string]string{
				"message": "Failed to parse CHALLENGE_RESPONSE",
				"error":   err.Error(),
			},
		})
		return false, err
	}

	if len(decodedChallengeResponse) != 64 {
		conn.WriteJSON(map[string]string{
			"type": "SIGNATURE_MISMATCH",
			"data": "Expected a 64 byte signature, but got " + strconv.Itoa(len(decodedChallengeResponse)) + " bytes",
		})
		return false, nil
	}

	r := &big.Int{}
	s := &big.Int{}

	r.SetBytes(decodedChallengeResponse[:32])
	s.SetBytes(decodedChallengeResponse[32:])

	if !ecdsa.Verify(pubKey, payload, r, s) {
		conn.WriteJSON(map[string]string{
			"type": "SIGNATURE_MISMATCH",
		})
		return false, nil
	}

	conn.WriteJSON(map[string]string{
		"type": "SIGNATURE_MATCHES",
	})

	return true, nil
}
