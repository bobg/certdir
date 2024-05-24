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

	"github.com/bobg/certs"
)

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
		certfile = filepath.Join(dir, "fullchain.pem")
		keyfile  = filepath.Join(dir, "privkey.pem")
	)

	times, errptr := certs.Times(ctx, dir, interval)
	for range times {
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
		if err = enc.Encode(certs.X509KeyPair{CertPEMBlock: certpem, KeyPEMBlock: keypem}); err != nil {
			return errors.Wrap(err, "encoding key pair")
		}
	}

	if *errptr != nil {
		return *errptr
	}

	return nil
}
