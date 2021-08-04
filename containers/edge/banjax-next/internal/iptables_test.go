// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"reflect"
	"testing"
)

func TestIpAndTimestampToRuleSpec(t *testing.T) {
	ruleSpec := ipAndTimestampToRuleSpec("1.255.3.255", 1599232634)
	expected := []string{"-s", "1.255.3.255", "-j", "DROP", "-m", "comment", "--comment", "added:1599232634"}

	if !reflect.DeepEqual(ruleSpec, expected) {
		t.Errorf("did not get the right thing")
	}
}

func TestRuleToRuleSpec(t *testing.T) {
	ruleSpec, err := ruleToRuleSpec(`-A INPUT -s 1.2.3.5/32 -m comment --comment "added:1599210074" -j DROP`)
	if err != nil {
		t.Errorf(err.Error())
	}
	expected := []string{"-s", "1.2.3.5/32", "-m", "comment", "--comment", "added:1599210074", "-j", "DROP"}
	if !reflect.DeepEqual(ruleSpec, expected) {
		t.Errorf("did not get the right thing")
	}
}
