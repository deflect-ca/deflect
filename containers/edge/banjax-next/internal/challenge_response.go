// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

func ComputeHmac(secretKey string, expireTime time.Time, clientIp string) []byte {
	// XXX copying this from banjax. this is not a good KDF, but it probably doesn't matter
	derivedKey := sha256.New()
	derivedKey.Write([]byte(secretKey))

	expireTimeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expireTimeBytes, uint64(expireTime.Unix()))

	mac := hmac.New(sha1.New, derivedKey.Sum(nil))
	mac.Write(expireTimeBytes)
	mac.Write([]byte(clientIp))
	return mac.Sum(nil)
}

func CountZeroBitsFromLeft(bytes []byte) uint32 {
	zeroBitCount := uint32(0)
	for _, byte_ := range bytes {
		for bitIndex := 7; bitIndex >= 0; bitIndex-- {
			if (byte_ & (1 << bitIndex)) == 0 {
				zeroBitCount++
			} else {
				return zeroBitCount
			}
		}
	}
	return zeroBitCount
}

func ValidateExpirationAndHmac(secretKey string,
	expirationBytes []byte,
	nowTime time.Time,
	hmacFromClient []byte,
	clientIp string) error {

	expirationInt := binary.BigEndian.Uint64(expirationBytes)
	expirationTime := time.Unix(int64(expirationInt), 0) // XXX i don't like the cast
	if expirationTime.Sub(nowTime) < 0 {
		return errors.New(fmt.Sprintf("expiration time is in the past: %v", expirationTime))
	}

	expectedHmac := ComputeHmac(secretKey, expirationTime, clientIp)
	if !bytes.Equal(expectedHmac, hmacFromClient) { // XXX think about constant-time equal?
		return errors.New("hmac not what it should be")
	}

	return nil
}

func ParseCookie(cookieString string) ([]byte, []byte, []byte, error) {
	cookieBytes := make([]byte, 20+32+8)
	log.Println("cookieString: ", cookieString)

	cookieBytes, err := base64.StdEncoding.DecodeString(cookieString)
	if err != nil {
		// gin erroneously does a QueryUnescape() on the cookie, which turns '+' into ' '.
		// https://github.com/gin-gonic/gin/issues/1717
		cookieString = strings.ReplaceAll(cookieString, " ", "+")
		cookieBytes, err = base64.StdEncoding.DecodeString(cookieString)
		if err != nil {
			return nil, nil, nil, errors.New("bad base64")
		}
	}
	log.Println("cookieBytes: ", cookieBytes)

	if len(cookieBytes) != 20+32+8 {
		return nil, nil, nil, errors.New("bad length")
	}

	hmacFromClient := cookieBytes[0:20]
	solutionBytes := cookieBytes[20 : 20+32]
	expirationBytes := cookieBytes[20+32 : 20+32+8]

	log.Println("hmacFromClient: ", hmacFromClient)
	log.Println("solutionBytes1: ", solutionBytes)
	log.Println("expirationBytes: ", expirationBytes)
	return hmacFromClient, solutionBytes, expirationBytes, nil
}

func ValidateShaInvCookie(secretKey string,
	cookieString string,
	nowTime time.Time,
	clientIp string,
	expectedZeroBits uint32) error {

	hmacFromClient, solutionBytes, expirationBytes, err := ParseCookie(cookieString)
	if err != nil {
		return err
	}

	err = ValidateExpirationAndHmac(secretKey, expirationBytes, nowTime, hmacFromClient, clientIp)
	if err != nil {
		return err
	}

	maybeSolution := make([]byte, 20+32)
	copy(maybeSolution[0:], hmacFromClient)
	copy(maybeSolution[20:], solutionBytes)

	hashedMaybeSolution := sha256.New()
	hashedMaybeSolution.Write(maybeSolution)
	actualZeroBits := CountZeroBitsFromLeft(hashedMaybeSolution.Sum(nil))
	log.Printf("expected %d zero bits, found %d", expectedZeroBits, actualZeroBits)
	if actualZeroBits < expectedZeroBits {
		return errors.New("not enough zero bits in hash")
	}

	// no error means it's valid
	return nil
}

// the original plugin code was constructing `hash(hmac, hash(password))` on both sides.
// i guess the obvious thing to do would be to just send the plaintext password like most
// login forms do, but we still support non-https. the next most obvious thing would be to
// send `hash(password)`, but i guess that's easily reversible if `password` is in a dictionary.
// so i guess i will keep the `hash(hmac, hash(password))` construction and add this comment
// for future maintainers.
// [XXX don't have time to think about this now, but if hmac is visible to network observers,
// does that mean they could still do a dictionary attack against the password?]
func ValidatePasswordCookie(secretKey string,
	cookieString string,
	nowTime time.Time,
	clientIp string,
	hashedPassword []byte) error {

	hmacFromClient, solutionBytes, expirationBytes, err := ParseCookie(cookieString)
	if err != nil {
		return err
	}
	log.Println("solutionBytes2: ", solutionBytes)

	// we assume hmacFromClient is good later, so be careful about re-ordering this
	err = ValidateExpirationAndHmac(secretKey, expirationBytes, nowTime, hmacFromClient, clientIp)
	if err != nil {
		return err
	}

	log.Println("hashedPassword: ", hashedPassword)

	// we know the hmac is good at this point
	expectedSolution := make([]byte, 20+32)
	copy(expectedSolution[0:], hmacFromClient)
	copy(expectedSolution[20:], hashedPassword)

	hashedExpectedSolution := sha256.New()
	hashedExpectedSolution.Write(expectedSolution)
	expectedSolutionBytes := hashedExpectedSolution.Sum(nil)
	if !bytes.Equal(expectedSolutionBytes, solutionBytes) {
		log.Println("client solution: ", solutionBytes)
		log.Println("expected solution: ", expectedSolutionBytes)
		return errors.New("bad password")
	}

	// no error means it's valid
	return nil
}

func NewChallengeCookie(secretKey string, now time.Time, clientIp string) string {
	// expireTime := time.Now().Add(5 * time.Second) // XXX config
	expireTime := time.Now().Add(60 * time.Second) // XXX config

	cookieBytes := make([]byte, 20+32+8)
	hmacBytes := ComputeHmac(secretKey, expireTime, clientIp) // XXX really, don't forget about this
	copy(cookieBytes[0:20], hmacBytes[0:20])
	// cookieBytes[20:20+32] can keep their zero values
	binary.BigEndian.PutUint64(cookieBytes[20+32:20+32+8], uint64(expireTime.Unix()))

	return base64.StdEncoding.EncodeToString(cookieBytes)
}

func SolveChallengeForTesting(cookieString string) string {
	cookieBytes, err := base64.StdEncoding.DecodeString(cookieString)
	if err != nil {
		log.Println("!! error: ", err.Error())
		return "" // XXX
	}

	log.Println("solving this: ", cookieBytes)

	randInt := int64(0)
	for ; ; randInt++ {
		binary.BigEndian.PutUint64(cookieBytes[20+32-8:20+32], uint64(randInt)) // XXX i don't like the cast

		hashedMaybeSolution := sha256.New()
		hashedMaybeSolution.Write(cookieBytes[0 : 20+32])
		if CountZeroBitsFromLeft(hashedMaybeSolution.Sum(nil)) < 10 { // XXX config
			continue
		} else {
			break
		}
	}

	log.Println("solved this: ", cookieBytes)

	return base64.StdEncoding.EncodeToString(cookieBytes)
}
