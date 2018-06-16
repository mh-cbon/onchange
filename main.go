package main

import (
	"context"
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"time"
)

var (
	log = logAPI{}
)

func main() {
	var opts = struct {
		fp    string
		re    string
		quiet bool
		delay time.Duration
	}{}

	flag.StringVar(&opts.fp, "fp", "",
		"the prefered way to computethe finger print of a resource, one of etag|body|mod|re")
	flag.StringVar(&opts.re, "re", "",
		"the text that the resource should contain and the daemon should use to identify an update")
	flag.DurationVar(&opts.delay, "d", time.Duration(time.Second),
		"pause between each test of the resource")

	flag.BoolVar(&opts.quiet, "q", false,
		"stfu")

	flag.Parse()

	log.SetQuiet(opts.quiet)

	args := flag.Args()

	if len(args) < 2 {
		log.Fatal("invalid command line: onchange <resource> <command>")
	}

	resource := args[0]
	cmdLine := args[1:]

	var re *regexp.Regexp
	if opts.re != "" {
		re = regexp.MustCompile(opts.re)
	}

	penTester := getPentester(resource, opts.fp, re)
	if penTester == nil {
		log.Fatal("failed to identify the resource type for the resource %q", resource)
	}

	trigger := buildCmdLineTrigger(penTester, cmdLine)
	if trigger == nil {
		log.Fatal("failed to build a trigger for the given command line %q", cmdLine)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collectAndCheckFingerPrints(ctx, penTester, trigger, opts.delay)

	<-cancelNotify()
	cancel()

	// dont wait for goroutine finish,
	// some resource fetcher are not context aware
	// they would block.
	// <-done
	// <-done

}

func collectAndCheckFingerPrints(ctx context.Context, penTester resourcePentester, trigger *resourceChangeTrigger, delay time.Duration) chan bool {

	done := make(chan bool)
	fingerprintCollector := make(chan fingerPrinter)

	go func() {
		defer func() { done <- true }()
		for {
			fp, err := penTester.Pentest()
			if err != nil {
				log.Error("failed to fetch %q, err=%v", penTester.Resource(), err)
			} else {
				log.Print("collected fingerprint %v", fp)
			}
			fingerprintCollector <- fp
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				close(fingerprintCollector)
				return
			}
		}
	}()

	go func() {
		defer func() { done <- true }()
		var fp fingerPrinter
		var newFP fingerPrinter
		first := true
		for {
			select {
			case <-ctx.Done():
				return
			case newFP = <-fingerprintCollector:
				if !compareFingerPrints(fp, newFP) {
					log.Print("resource changed %q", penTester.Resource())
					fp = newFP
					if !first {
						if err := trigger.Execute(); err != nil {
							log.Error("failed to execute the trigger %q, err=%v", trigger, err)
						}
					}
				}
			}
			first = false
		}
	}()

	return done
}

func cancelNotify() chan os.Signal {
	sig := make(chan os.Signal, 10)
	signal.Notify(sig, os.Interrupt, os.Kill)
	return sig
}

type fingerPrinter interface {
	Fingerprint() string
	Timestamp() time.Time
}

func compareFingerPrints(left, right fingerPrinter) (same bool) {
	if left == right {
		return true
	}
	if left == nil && right != nil {
		return false
	}
	if left != nil && right == nil {
		return false
	}
	leftT := fmt.Sprintf("%T", left)
	rightT := fmt.Sprintf("%T", right)

	if leftT != rightT {
		return false
	}

	leftFP := left.Fingerprint()
	rightFP := right.Fingerprint()

	return leftFP == rightFP
}

type resourceChangeTrigger struct {
	tester  resourcePentester
	trigger func() error
}

func (r resourceChangeTrigger) Execute() error {
	return r.trigger()
}

func buildCmdLineTrigger(penTester resourcePentester, cmdLine []string) *resourceChangeTrigger {
	trigger := func() error {
		bin := cmdLine[0]
		args := []string{}
		if len(cmdLine) > 1 {
			args = cmdLine[1:]
		}
		cmd := exec.Command(bin, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		return cmd.Run()
	}

	return &resourceChangeTrigger{
		tester:  penTester,
		trigger: trigger,
	}
}

// resourcePentester knows how to deal with a given resource string
// and returns an identifier of its state that is usable to detect changes.
type resourcePentester interface {
	// Must returns one those type: time.Time, sha1sum, contentExtract
	Pentest() (fingerPrinter, error)
	// Resource uri to pentest
	Resource() string
}

func getPentester(uri string, fpSum string, re *regexp.Regexp) (ret resourcePentester) {
	if strings.HasPrefix(uri, "file://") {
		ret = &filePentester{resource: resource{uri: uri, preferedSum: fpSum, re: re}}
	} else if strings.HasPrefix(uri, "http://") {
		client := http.DefaultClient
		client.Timeout = time.Second * 10
		ret = &urlPentester{resource: resource{uri: uri, preferedSum: fpSum, re: re}, client: client}
	} else {
		ret = &filePentester{resource: resource{uri: uri, preferedSum: fpSum, re: re}}
	}
	return ret
}

type sha1sum struct {
	resource    string
	fingerprint string
	timestamp   time.Time
}

func (s sha1sum) Fingerprint() string {
	return s.fingerprint
}
func (s sha1sum) Timestamp() time.Time {
	return s.timestamp
}
func (s sha1sum) String() string {
	return fmt.Sprintf("%v fp:%q timestamp:%v", s.resource, s.fingerprint, s.timestamp.Format(time.RubyDate))
}

type resource struct {
	uri         string
	preferedSum string
	re          *regexp.Regexp
}

func (r *resource) Resource() string {
	return r.uri
}

type filePentester struct {
	resource
}

func (f *filePentester) Pentest() (fingerPrinter, error) {
	uri := f.Resource()
	var ret fingerPrinter
	var sum string
	if f.preferedSum == "mod" || f.preferedSum == "" {
		s, err := os.Stat(uri)
		if err != nil {
			return nil, err
		}
		sum = fmt.Sprintf("%v", s.ModTime())
	} else if f.preferedSum == "body" {
		x, err := f.bodySum()
		if err != nil {
			return nil, err
		}
		sum = x
	} else if f.preferedSum == "etag" {
		s, err := os.Stat(uri)
		if err != nil {
			return nil, err
		}
		hasher := sha1.New()
		fmt.Fprintf(hasher, "isdir=%v", s.IsDir())
		fmt.Fprintf(hasher, "modtime=%v", s.ModTime())
		fmt.Fprintf(hasher, "size=%v", s.Size())
		sum = fmt.Sprintf("%x", hasher.Sum(nil))
	} else if f.preferedSum == "re" {
		x, err := f.bodyMatch()
		if err != nil {
			return nil, err
		}
		sum = x
	}
	ret = sha1sum{
		resource:    uri,
		fingerprint: sum,
		timestamp:   time.Now(),
	}
	return ret, nil
}
func (f *filePentester) bodyMatch() (string, error) {
	data, err := ioutil.ReadFile(f.Resource())
	if err != nil {
		return "", err
	}
	sum := f.re.Find(data)
	if len(sum) == 0 {
		return "", fmt.Errorf("regexp does not match")
	}
	return string(sum), nil
}
func (f *filePentester) bodySum() (string, error) {
	hasher := sha1.New()
	r, err := os.Open(f.Resource())
	if err != nil {
		return "", err
	}
	defer r.Close()
	_, err = io.Copy(hasher, r)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

type urlPentester struct {
	resource
	client *http.Client
}

func (f *urlPentester) Pentest() (fingerPrinter, error) {
	uri := f.Resource()
	res, err := f.client.Get(uri)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var sum string
	if f.preferedSum == "" {
		sum = res.Header.Get("ETag")
		if sum == "" {
			sum = res.Header.Get("Last-Modified")
		}
		if sum == "" {
			x, err := f.bodySum(res.Body)
			if err != nil {
				return nil, err
			}
			sum = x
		}
	} else if f.preferedSum == "etag" {
		sum = res.Header.Get("ETag")
	} else if f.preferedSum == "mod" {
		sum = res.Header.Get("Last-Modified")
	} else if f.preferedSum == "body" {
		x, err := f.bodySum(res.Body)
		if err != nil {
			return nil, err
		}
		sum = x
	} else if f.preferedSum == "re" {
		x, err := f.bodyMatch(res.Body)
		if err != nil {
			return nil, err
		}
		sum = x
	}
	fp := sha1sum{
		resource:    uri,
		fingerprint: sum,
		timestamp:   time.Now(),
	}
	return fp, nil
}
func (f *urlPentester) bodyMatch(body io.ReadCloser) (string, error) {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return "", err
	}
	sum := f.re.Find(data)
	if len(sum) == 0 {
		return "", fmt.Errorf("regexp does not match")
	}
	return string(sum), nil
}
func (f *urlPentester) bodySum(body io.ReadCloser) (string, error) {
	hasher := sha1.New()
	_, err := io.Copy(hasher, body)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

type logAPI struct {
	stfu bool
}

func (l *logAPI) SetQuiet(stfu bool) {
	l.stfu = stfu
}

func (l logAPI) Print(f string, args ...interface{}) {
	if l.stfu {
		return
	}
	if len(args) == 0 {
		stdlog.Print(f + "\n")
	} else {
		stdlog.Printf(f+"\n", args...)
	}
}

func (l logAPI) Fatal(f string, args ...interface{}) {
	if len(args) == 0 {
		stdlog.Fatalf(f + "\n")
	} else {
		stdlog.Fatalf(f+"\n", args...)
	}
}

func (l logAPI) Error(f string, args ...interface{}) {
	if len(args) == 0 {
		stdlog.Print(f + "\n")
	} else {
		stdlog.Printf(f+"\n", args...)
	}
}
