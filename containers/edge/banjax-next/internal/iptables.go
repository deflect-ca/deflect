// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ipAndTimestampToRuleSpec(ip string, timestamp int64) []string {
	return []string{"-s", ip, "-j", "DROP", "-m", "comment",
		"--comment", fmt.Sprintf("added:%d", timestamp)}
}

// to Delete a rule returned from List, we have to fix it up a little
// basically change this string: `-A INPUT -s 1.2.3.5/32 -m comment --comment "added:1599210074" -j DROP`
// into this slice: ["-s" "1.2.3.5/32" "-m" "comment" "--comment" "added:1599210074" "-j" "DROP"]
func ruleToRuleSpec(rule string) ([]string, error) {
	entryFields := strings.Split(rule, " ")
	if len(entryFields) < 3 {
		return entryFields, errors.New("Not enough fields in this rule")
	}
	// we want to skip the "-A" and "INPUT" fields
	entryFields = entryFields[2:]
	// alright, this is a bit annoying. the entries from List() have the comment string quoted,
	// like `--comment "added:1234"`, but Delete() requires each field to be unquoted...
	for i, _ := range entryFields {
		if strings.HasPrefix(entryFields[i], "\"added:") {
			unquotedField, err := strconv.Unquote(entryFields[i])
			if err != nil {
				return entryFields, errors.New("Unquote failed")
			}
			entryFields[i] = unquotedField
		}
	}
	return entryFields, nil
}

func RunIpBanExpirer(config *Config, wg *sync.WaitGroup) {
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("iptables.New() failed: %v", err)
		return
	}

	for {
		ruleList, err := ipt.List("filter", "INPUT")
		if err != nil {
			log.Printf("List failed: %v", err)
			return
		}

		// ti := time.Now()
		// tiMs := int64(time.Nanosecond) * ti.UnixNano() / int64(time.Millisecond)
		// fmt.Printf("timeUnixMilli: %d\n", tiMs)
		// i := uint64(0)
		for _, rule := range ruleList {
			timestampRegex := regexp.MustCompile(`added:(\d*)`)
			timestampMatches := timestampRegex.FindStringSubmatch(rule)
			if len(timestampMatches) < 2 {
				continue
			}

			addedTimeInt, err := strconv.ParseInt(timestampMatches[1], 10, 64)
			if err != nil {
				log.Println("could not parse an int where the timestamp should be: ", timestampMatches[1])
				continue
			}

			addedTime := time.Unix(addedTimeInt, 0)

			if time.Now().Sub(addedTime) > (time.Second * time.Duration(config.IptablesBanSeconds)) {
				ruleSpec, err := ruleToRuleSpec(rule)
				if err != nil {
					log.Println(err)
					continue
				}

				err = ipt.Delete("filter", "INPUT", ruleSpec...)
				if err != nil {
					log.Printf("Delete failed")
					continue
				}

				log.Println("Delete succeeded")
			}
			// i++
			// if i > 100 {
			// 	ti2 := time.Now()
			// 	ti2Ms := int64(time.Nanosecond) * ti2.UnixNano() / int64(time.Millisecond)
			// 	fmt.Printf("deleted 100 rules in %d ms\n", ti2Ms - tiMs)
			// 	tiMs = ti2Ms
			// 	i = 0
			// }
		}
		time.Sleep(time.Second * time.Duration(config.IptablesUnbannerSeconds))
	}
}

type BannerInterface interface {
	BanOrChallengeIp(config *Config, ip string, decision Decision)
    LogRegexBan(logTime time.Time, ip string, ruleName string, logLine string, decision Decision)
    LogFailedChallengeBan( ip string, challengeType string, host string, path string, tooManyFailedChallengesThreshold int,
        userAgent string, decision Decision)
}

type Banner struct {
	DecisionListsMutex *sync.Mutex
	DecisionLists      *DecisionLists
	Logger             *log.Logger
}

func purgeNginxAuthCacheForIp(ip string) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:80/auth_requests/%s*", ip), nil) // XXX
	if err != nil {
		log.Println("purgeNginxAuthCacheForIp() NewRequest() failed!")
		return
	}

	req.Host = "cache_purge"
	response, err := client.Do(req)
	if err != nil {
		log.Println("purgeNginxAuthCacheForIp() Get() failed!")
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("ioutil.ReadAll() failed!")
		return
	}

	defer response.Body.Close()

	if bytes.Contains(body, []byte("Successful purge")) {
		log.Println("purgeNginxAuthCacheForIp() got 'Successful purge' response'")
	} else {
		log.Println("purgeNginxAuthCacheForIp() DID NOT GET 'Successful purge' response'")
		log.Println("instead got: ", string(body))
	}
}
func (b Banner) LogRegexBan(
    logTime time.Time,
    ip string,
    ruleName string,
    logLine string,
    decision Decision,
) {
    timeString := logTime.Format("[2006-01-02T15:04:05]")  // XXX should this be the log timestamp or time.Now()?

    words := strings.Split(logLine, " ")
    log.Println(words)
    method := words[0]
    host := words[1]
    path := words[3]
    userAgent := words[5]

    b.Logger.Printf("%s, %s, matched regex rule %s, %s, \"http:///%s\", %s, %q, banned\n",
        ip, timeString, ruleName, method, path, host, userAgent,
    )
}

func (b Banner) LogFailedChallengeBan(
    ip string,
    challengeType string,
    host string,
    path string,
    tooManyFailedChallengesThreshold int,
    userAgent string,
    decision Decision,
) {
    timeString := time.Now().Format("[2006-01-02T15:04:05]")

    b.Logger.Printf("%s, %s, failed challenge %s for host %s %d times, \"http://%s/%s\", %s, %q, banned\n",
        ip, timeString, challengeType, host, tooManyFailedChallengesThreshold, host, path, host, userAgent,
    )
}

func (b Banner) BanOrChallengeIp(
    config *Config,
    ip string,
    decision Decision,
) {
	log.Println("BanOrChallengeIp()")

	updateExpiringDecisionLists(
		config,
		ip,
		&(*b.DecisionListsMutex),
		&(*b.DecisionLists),
		time.Now(),
		decision,
	)

	if decision == IptablesBlock {
		banIp(config, ip)
	}
}

func banIp(config *Config, ip string) {
	if ip == "127.0.0.1" {
		log.Println("Not going to block localhost")
		return
	}

	ipt, err := iptables.New()

	ruleSpec := ipAndTimestampToRuleSpec(ip, time.Now().Unix())
	log.Printf("!!!!! ADDING RULESPEC: %s\n", ruleSpec)
	err = ipt.Append("filter", "INPUT", ruleSpec...)
	if err != nil {
		//log.Println("Append failed")
		return
	}
	log.Println("Append succeeded")
}

// XXX
func BanIp(config *Config, ip string) {
	banIp(config, ip)
}
