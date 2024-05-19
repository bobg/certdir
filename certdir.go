package certdir

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/bobg/errors"
)

// FromDir produces [tls.Certificate] values from a directory.
// The directory is polled at the given interval for new fullchain.pem and privkey.pem files.
// When found, they are bundled up as a [tls.Certificate] and sent on the returned channel.
// This continues until the context is canceled or an error occurs.
//
// The returned error pointer can be used to check for an error in the polling goroutine,
// but only after the channel is closed.
func FromDir(ctx context.Context, dir string, interval time.Duration) (<-chan tls.Certificate, *error) {
	var (
		certfile = filepath.Join(dir, "fullchain.pem")
		keyfile  = filepath.Join(dir, "privkey.pem")
		ch       = make(chan tls.Certificate)
		errptr   = new(error)
	)

	go func() {
		defer close(ch)

		var lastCertTime, lastKeyTime time.Time

		for {
			newCertTime, newKeyTime, err := Times(dir)
			if err != nil {
				*errptr = errors.Wrapf(err, "checking times in %s", dir)
				return
			}

			if !lastCertTime.Equal(newCertTime) || !lastKeyTime.Equal(newKeyTime) {
				certpem, err := os.ReadFile(certfile)
				if err != nil {
					*errptr = errors.Wrapf(err, "reading %s", certfile)
					return
				}
				keypem, err := os.ReadFile(keyfile)
				if err != nil {
					*errptr = errors.Wrapf(err, "reading %s", keyfile)
					return
				}
				cert, err := tls.X509KeyPair(certpem, keypem)
				if err != nil {
					*errptr = errors.Wrap(err, "creating certificate object")
					return
				}
				select {
				case <-ctx.Done():
					*errptr = errors.Wrap(ctx.Err(), "sending certificate on channel")
				case ch <- cert:
				}

				lastCertTime, lastKeyTime = newCertTime, newKeyTime
			}

			t := time.NewTimer(interval)
			defer t.Stop()

			select {
			case <-ctx.Done():
				*errptr = ctx.Err()
			case <-t.C:
			}
		}
	}()

	return ch, errptr
}

// FromCommand produces [tls.Certificate] values by running a shell command in a subprocess.
// The shell command must produce JSON-encoded [X509KeyPair] values on its standard output.
// A goroutine parses these into certificates and sends them on the returned channel.
// This continues until the context is canceled or an error occurs.
//
// The returned func() error must be called to release resources after the channel is closed.
// Its result may indicate an error encountered during processing.
func FromCommand(ctx context.Context, cmdstr string) (<-chan tls.Certificate, func() error, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdstr)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating stdout pipe")
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, errors.Wrapf(err, "starting %s", cmd)
	}

	ch := make(chan tls.Certificate)
	dec := json.NewDecoder(stdout)

	errptr := new(error)

	go func() {
		for {
			var pair X509KeyPair
			if err := dec.Decode(&pair); err != nil {
				*errptr = errors.Wrap(err, "decoding JSON")
				return
			}
			cert, err := tls.X509KeyPair(pair.CertPEMBlock, pair.KeyPEMBlock)
			if err != nil {
				*errptr = errors.Wrap(err, "creating key pair")
				return
			}
			select {
			case <-ctx.Done():
				*errptr = ctx.Err()
				return

			case ch <- cert:
			}
		}
	}()

	wait := func() error {
		err := cmd.Wait()
		if *errptr != nil {
			return *errptr
		}
		return err
	}

	return ch, wait, nil
}

// Times returns the times of the cert and key files in a directory.
func Times(dir string) (cert, key time.Time, err error) {
	var (
		certfile = filepath.Join(dir, "fullchain.pem")
		keyfile  = filepath.Join(dir, "privkey.pem")
	)

	info, err := os.Stat(certfile)
	if err != nil {
		return cert, key, errors.Wrapf(err, "statting %s", certfile)
	}
	cert = info.ModTime()

	info, err = os.Stat(keyfile)
	if err != nil {
		return cert, key, errors.Wrapf(err, "statting %s", keyfile)
	}
	key = info.ModTime()

	return cert, key, nil
}

// X509KeyPair is a pair containing an X.509 certificate and private key, both PEM-encoded.
type X509KeyPair struct {
	CertPEMBlock, KeyPEMBlock []byte
}
