package certdir

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"time"

	"github.com/bobg/errors"
)

// Run polls a directory for fullchain.pem and privkey.pem files.
// Each time it finds a newer one of either file,
// it bundles up their contents as a [tls.Certificate]
// and passes it to the provided function,
// which runs in a goroutine.
// If the function is already running in a goroutine when a new certificate is ready,
// Run cancels its context and waits for it to return before starting a new goroutine.
//
// If f returns an error, Run returns it,
// unless the error is [context.Canceled] because Run canceled its context.
// Otherwise, Run continues until _its_ context is canceled.
func Run(ctx context.Context, dir string, interval time.Duration, f func(context.Context, tls.Certificate) error) error {
	var (
		last  timePair
		errCh chan error
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// For overall cancellation, e.g. on error return.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// For canceling a single invocation of f.
	fctx, fcancel := context.WithCancel(ctx)
	defer fcancel()

	for {
		next, err := check(dir)
		if err != nil {
			return errors.Wrap(err, "checking directory")
		}
		if !next.equal(last) {
			// Cancel the current invocation of f, if there is one.

			if errCh != nil {
				fcancel()
				err := <-errCh
				if err != nil {
					if !errors.Is(err, context.Canceled) || ctx.Err() != nil {
						return err
					}
				}
			}

			// Load the new cert and key.

			var (
				certfile = filepath.Join(dir, "fullchain.pem")
				keyfile  = filepath.Join(dir, "privkey.pem")
			)
			cert, err := tls.LoadX509KeyPair(certfile, keyfile)
			if err != nil {
				return errors.Wrapf(err, "loading cert and key from %s and %s", certfile, keyfile)
			}

			// Start a new invocation of f.

			fctx, fcancel = context.WithCancel(ctx)
			defer fcancel()

			errCh = make(chan error, 1)
			go func() {
				errCh <- f(fctx, cert)
				close(errCh)
			}()

			last = next
		}

		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			// Continue to the next iteration.

		case err := <-errCh:
			return err
		}
	}
}

type timePair struct {
	cert, key time.Time
}

func (p timePair) equal(other timePair) bool {
	return p.cert.Equal(other.cert) && p.key.Equal(other.key)
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
