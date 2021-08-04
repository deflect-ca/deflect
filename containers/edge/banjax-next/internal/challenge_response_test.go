// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestCountZeroBitsFromLeft(t *testing.T) {
	noZeroBits1 := make([]byte, 2)
	binary.BigEndian.PutUint16(noZeroBits1, 0xffff)
	zeroBitCount := CountZeroBitsFromLeft(noZeroBits1)
	if zeroBitCount != 0 {
		t.Errorf("0xffff should not have any zero bits")
	}

	oneZeroBit := make([]byte, 2)
	binary.BigEndian.PutUint16(oneZeroBit, 0x7fff)
	zeroBitCount = CountZeroBitsFromLeft(oneZeroBit)
	if zeroBitCount != 1 {
		t.Errorf("0x7fff should have one zero bit (from the left)")
	}

	twoZeroBits := make([]byte, 2)
	binary.BigEndian.PutUint16(twoZeroBits, 0x3fff)
	zeroBitCount = CountZeroBitsFromLeft(twoZeroBits)
	if zeroBitCount != 2 {
		t.Errorf("0x3fff should have two zero bits (from the left)")
	}

	notThreeZeroBits := make([]byte, 2)
	binary.BigEndian.PutUint16(notThreeZeroBits, 0x2fff)
	zeroBitCount = CountZeroBitsFromLeft(notThreeZeroBits)
	if zeroBitCount != 2 {
		t.Errorf("0x2fff should have two zero bits (from the left)")
	}
}

func TestValidateShaInvCookie(t *testing.T) {
	now := time.Now()

	err := ValidateShaInvCookie("password", "bad base64", now, "x.x.x.x", 10)
	if err.Error() != "bad base64" {
		t.Errorf("should have got an error")
	}

	// gin will turn '+' into ' ', so we need to fix it up ourselves
	err = ValidateShaInvCookie("password", "A  =", now, "x.x.x.x", 10)
	if err.Error() == "bad base64" {
		t.Errorf("we need to turn ' ' into '+' because of a gin bug")
	}

	err = ValidateShaInvCookie("password", "A++=", now, "x.x.x.x", 10)
	if err.Error() != "bad length" {
		t.Errorf("should have got an error")
	}

	expiredChallengeCookie := NewChallengeCookie(now.Add(2*time.Hour), "1.2.3.4")
	unsolvedChallengeCookie := NewChallengeCookie(now, "1.2.3.4")

	err = ValidateShaInvCookie("password", expiredChallengeCookie, now, "1.2.3.4", 10)
	if strings.HasPrefix(err.Error(), "expiration time is in the past") {
		t.Errorf("should have got an error")
	}

	err = ValidateShaInvCookie("password", unsolvedChallengeCookie, now, "x.x.x.x", 10)
	if err.Error() != "hmac not what it should be" {
		t.Errorf("should have got an error")
	}

	err = ValidateShaInvCookie("password", unsolvedChallengeCookie, now, "1.2.3.4", 12)
	if err.Error() != "not enough zero bits in hash" {
		t.Errorf("should have got an error")
	}

	solvedChallengeCookie := SolveChallengeForTesting(unsolvedChallengeCookie)

	err = ValidateShaInvCookie("password", solvedChallengeCookie, now, "1.2.3.4", 10)
	if err != nil {
		t.Errorf("should NOT have gotten an error: %s", err.Error())
	}
}
