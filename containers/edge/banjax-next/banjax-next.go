// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"encoding/json"
	"flag"
	"github.com/equalitie/banjax-next/internal"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"
)

func load_config(config *internal.Config, standaloneTestingPtr *bool, configFilenamePtr *string, restartTime int) {
	config.RestartTime = restartTime
	config.ReloadTime = int(time.Now().Unix()) // XXX

	hostname, err := os.Hostname()
	if err != nil {
		log.Println("couldn't get hostname! using dummy")
		hostname = "unknown-hostname"
	}
	config.Hostname = hostname

	configBytes, err := ioutil.ReadFile(*configFilenamePtr) // XXX allow different location
	if err != nil {
		panic("couldn't read config file!")
	}
	// log.Printf("read %v\n", string(configBytes[:]))

	config.StandaloneTesting = *standaloneTestingPtr
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		log.Printf("%v\n", err)
		panic("couldn't parse config file!")
	}
	log.Printf("read %v\n", *config)
	// XXX config
	challengerBytes, err := ioutil.ReadFile("./internal/sha-inverse-challenge.html")
	if err != nil {
		panic("!!! couldn't read sha-inverse-challenge.html")
	}
	config.ChallengerBytes = challengerBytes

	passwordPageBytes, err := ioutil.ReadFile("./internal/password-protected-path.html")
	if err != nil {
		panic("!!! couldn't read password-protected-path.html")
	}
	config.PasswordPageBytes = passwordPageBytes

	for i, _ := range config.RegexesWithRates {
		re, err := regexp.Compile(config.RegexesWithRates[i].Regex)
		if err != nil {
			panic("bad regex")
		}
		config.RegexesWithRates[i].CompiledRegex = *re
	}
}

func main() {
	standaloneTestingPtr := flag.Bool("standalone-testing", false, "makes it easy to test standalone")
	configFilenamePtr := flag.String("config-file", "/etc/banjax-next/banjax-next-config.yaml", "config file")
	flag.Parse()

	restartTime := int(time.Now().Unix()) // XXX

	log.Println("config file: ", *configFilenamePtr)

	config := internal.Config{}
	load_config(&config, standaloneTestingPtr, configFilenamePtr, restartTime)

	sighup_channel := make(chan os.Signal, 1)
	signal.Notify(sighup_channel, syscall.SIGHUP)
	// XXX i forgot i had this config reload functionality.
	// i don't think this will do everything it needs to. i think we'll need to restart
	// RunHttpServer, RunLogTailer, etc. because they might have internal state that
	// referenced old config values.
	go func() {
		for _ = range sighup_channel {
			log.Println("got SIGHUP; reloading config")
			load_config(&config, standaloneTestingPtr, configFilenamePtr, restartTime)
		}
	}()

	if config.StandaloneTesting {
		log.Println("!!! setting ServerLogFile to testing-log-file.txt")
		config.ServerLogFile = "testing-log-file.txt"
		config.BanningLogFile = "banning-log-file.txt"
	}

	if config.ServerLogFile == "" {
		panic("config needs server_log_file!!")
	}

	// XXX should i verify all the config stuff is here before we get further?
	if config.IptablesBanSeconds == 0 {
		panic("config needs iptables_ban_seconds!!")
	}

	// XXX should i verify all the config stuff is here before we get further?
	if len(config.KafkaBrokers) < 1 {
		panic("config needs kafka_brokers!!")
	}
	log.Println(config.KafkaBrokers)

	// XXX protects decisionLists
	var decisionListsMutex sync.Mutex
	decisionLists := internal.ConfigToDecisionLists(&config)

	passwordProtectedPaths := internal.ConfigToPasswordProtectedPaths(&config)

	// XXX protects ipToRegexStates and failedChallengeStates
	// (why both? because there are too many parameters already?)
	var rateLimitMutex sync.Mutex
	ipToRegexStates := internal.IpToRegexStates{}
	failedChallengeStates := internal.FailedChallengeStates{}

	// XXX this interface exists to make mocking out the iptables stuff
	// in testing easier. there might be a better way to do it.
	// at least it encapsulates the decisionlists and their mutex
	// together, which should probably happen for the other things
	// protected by a mutex.
	banningLogFile, err := os.OpenFile(config.BanningLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer banningLogFile.Close()
	banner := internal.Banner{
		&decisionListsMutex,
		&decisionLists,
		log.New(banningLogFile, "", 0),
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go internal.RunHttpServer(
		&config,
		&decisionListsMutex,
		&decisionLists,
		&passwordProtectedPaths,
		&rateLimitMutex,
		&ipToRegexStates,
		&failedChallengeStates,
		banner,
		&wg,
	)

	wg.Add(1)
	go internal.RunLogTailer(
		&config,
		banner,
		&rateLimitMutex,
		&ipToRegexStates,
		&wg,
	)

	wg.Add(1)
	go internal.RunIpBanExpirer(
		&config,
		&wg,
	)

	wg.Add(1)
	go internal.RunKafkaReader(
		&config,
		&decisionListsMutex,
		&decisionLists,
		&wg,
	)

	wg.Add(1)
	go internal.RunKafkaWriter(
		&config,
		&wg,
	)

	metricsLogFileName := ""
	if config.StandaloneTesting {
		metricsLogFileName = "list-metrics.log"
	} else {
		metricsLogFileName = config.MetricsLogFileName
	}

	metricsLogFile, _ := os.Create(metricsLogFileName)
	defer metricsLogFile.Close()
	metricsLogEncoder := json.NewEncoder(metricsLogFile)

	// statusTicker := time.NewTicker(5 * time.Second)
	expireTicker := time.NewTicker(9 * time.Second)
	statusTicker := time.NewTicker(19 * time.Second)
	metricsTicker := time.NewTicker(29 * time.Second)
	go func() {
		for {
			select {
			case <-statusTicker.C:
				log.Println("calling ReportStatusMessage")
				internal.ReportStatusMessage(
					&config,
				)
			case <-expireTicker.C:
				internal.RemoveExpiredDecisions(
					&decisionListsMutex,
					&decisionLists,
				)
			case <-metricsTicker.C:
				internal.WriteMetricsToEncoder(
					metricsLogEncoder,
					&decisionListsMutex,
					&decisionLists,
					&rateLimitMutex,
					&ipToRegexStates,
					&failedChallengeStates,
				)
			}
		}
	}()

	wg.Wait()
}
