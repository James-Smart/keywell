package password

import (
	"context"
	"encoding/base64"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// cheapHash is an argon2id hash of pw at a tiny cost, so tests can run
// many verifies quickly.
func cheapHash(pw string) string {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(pw), salt, 1, 8, 1, 32)
	return "$argon2id$v=19$m=8,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key)
}

// useSlots gives the package n hashing slots and hook (run inside each
// slot) until the test ends.
func useSlots(t *testing.T, n int, hook func()) {
	t.Helper()
	oldSlots, oldHook := slots, testHookInSlot
	slots, testHookInSlot = make(chan struct{}, n), hook
	t.Cleanup(func() { slots, testHookInSlot = oldSlots, oldHook })
}

func TestDefaultSlots(t *testing.T) {
	if want := max(2, min(4, runtime.NumCPU())); cap(slots) != want {
		t.Fatalf("%d slots, want %d", cap(slots), want)
	}
}

// However many requests check passwords at once, at most the number of
// slots hash at a time, which bounds the memory argon2 takes.
func TestVerifyCtxAndHashCtxShareTheSlots(t *testing.T) {
	var running, most atomic.Int32
	useSlots(t, 2, func() {
		n := running.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		running.Add(-1)
	})
	const pw = "correct horse battery staple"
	h := cheapHash(pw)
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for range 20 {
		wg.Go(func() {
			if ok, err := VerifyCtx(context.Background(), pw, h); !ok || err != nil {
				errs <- errors.Join(errors.New("VerifyCtx did not match"), err)
			}
		})
	}
	for range 4 { // native cost: slower, so fewer
		wg.Go(func() {
			if _, err := HashCtx(context.Background(), pw); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if m := most.Load(); m != 2 {
		t.Fatalf("at most %d hashes ran at once, want 2 (the number of slots)", m)
	}
}

// A request whose context ends while it waits for a slot gives up with
// ErrBusy, as does one whose context has already ended.
func TestBusyWhenNoSlotComesFree(t *testing.T) {
	useSlots(t, 2, nil)
	h := cheapHash("pw")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err := VerifyCtx(cancelled, "pw", h); ok || !errors.Is(err, ErrBusy) {
		t.Fatalf("VerifyCtx(cancelled) = %v, %v; want false, ErrBusy", ok, err)
	}
	if hash, err := HashCtx(cancelled, "pw"); hash != "" || !errors.Is(err, ErrBusy) {
		t.Fatalf("HashCtx(cancelled) = %q, %v; want ErrBusy", hash, err)
	}

	slots <- struct{}{} // every slot taken
	slots <- struct{}{}
	defer func() { <-slots; <-slots }()
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if ok, err := VerifyCtx(ctx, "pw", h); ok || !errors.Is(err, ErrBusy) {
		t.Fatalf("VerifyCtx with every slot taken = %v, %v; want false, ErrBusy", ok, err)
	}
	ctx, stop = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if _, err := HashCtx(ctx, "pw"); !errors.Is(err, ErrBusy) {
		t.Fatalf("HashCtx with every slot taken: %v; want ErrBusy", err)
	}
}

// A hash that names no usable password, or an unknown format, is refused
// before a slot is taken, as Verify refuses it.
func TestVerifyCtxUnusableNeedsNoSlot(t *testing.T) {
	useSlots(t, 1, nil)
	slots <- struct{}{}
	defer func() { <-slots }()
	if _, err := VerifyCtx(context.Background(), "pw", ""); !errors.Is(err, ErrUnusable) {
		t.Fatalf("VerifyCtx(empty hash): %v; want ErrUnusable", err)
	}
}
