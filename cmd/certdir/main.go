// Command certdir polls a directory for fullchain.pem and privkey.pem files.
// Each time it finds a newer one of either file,
// it bundles up their contents as JSON and emits it to stdout.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/bobg/errors"

	"github.com/bobg/certdir"
)

type timePair struct {
	cert, key time.Time
}

func (p timePair) equal(other timePair) bool {
	return p.cert.Equal(other.cert) && p.key.Equal(other.key)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var interval time.Duration

	flag.DurationVar(&interval, "interval", time.Hour, "directory polling interval")
	flag.Parse()

	if flag.NArg() != 1 {
		return fmt.Errorf("usage: %s [-interval DURATION] DIR", os.Args[0])
	}

	dir := flag.Arg(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// Cancel the context when standard input closes.
		io.Copy(io.Discard, os.Stdin)
		cancel()
	}()

	var (
		lastCertTime, lastKeyTime time.Time
		certfile                  = filepath.Join(dir, "fullchain.pem")
		keyfile                   = filepath.Join(dir, "privkey.pem")
		ticker                    = time.NewTicker(interval)
	)
	defer ticker.Stop()

	for {
		newCertTime, newKeyTime, err := certdir.Times(dir)
		if err != nil {
			return errors.Wrapf(err, "checking directory %s", dir)
		}
		if !newCertTime.Equal(lastCertTime) || !newKeyTime.Equal(lastKeyTime) {
			certpem, err := os.ReadFile(certfile)
			if err != nil {
				return errors.Wrapf(err, "reading %s", certfile)
			}
			keypem, err := os.ReadFile(keyfile)
			if err != nil {
				return errors.Wrapf(err, "reading %s", keyfile)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err = enc.Encode(certdir.X509KeyPair{CertPEMBlock: certpem, KeyPEMBlock: keypem}); err != nil {
				return errors.Wrap(err, "encoding key pair")
			}

			lastCertTime, lastKeyTime = newCertTime, newKeyTime
		}
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			// Wait for the next tick.
		}
	}
}

func check(dir string) (timePair, error) {
	info, err := os.Stat(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return timePair{}, errors.Wrapf(err, "statting %s/fullchain.pem", dir)
	}
	certTime := info.ModTime()

	info, err = os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return timePair{}, errors.Wrapf(err, "statting %s/privkey.pem", dir)
	}
	keyTime := info.ModTime()

	return timePair{cert: certTime, key: keyTime}, nil
}
