// Command refpeer-srtp is an SRTP oracle backed by pion/srtp.
//
// It exists so the PHP SRTP implementation can be checked against a real one rather than
// against itself: a round trip through a single implementation passes just as happily when
// both halves agree on the wrong wire format.
//
// It reads one JSON request per line on stdin and writes one JSON response per line on
// stdout. Keeping it line-driven means a test can drive many vectors through a single
// process, and keeps the PHP side to proc_open plus fgets.
//
//	{"op":"protect",       "profile":"...","key":"<hex>","packet":"<hex>"}
//	{"op":"unprotect",     "profile":"...","key":"<hex>","packet":"<hex>"}
//	{"op":"protect_rtcp",  "profile":"...","key":"<hex>","packet":"<hex>"}
//	{"op":"unprotect_rtcp","profile":"...","key":"<hex>","packet":"<hex>"}
//
// "key" is the master key concatenated with the master salt, exactly as SRTP keying
// material arrives from DTLS. Responses are {"result":"<hex>"} or {"error":"..."}.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pion/srtp/v3"
)

type request struct {
	Op      string `json:"op"`
	Profile string `json:"profile"`
	Key     string `json:"key"`
	Packet  string `json:"packet"`
}

type response struct {
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// profiles maps the SRTP protection profile names used in DTLS to pion's constants.
var profiles = map[string]srtp.ProtectionProfile{
	"AES_CM_128_HMAC_SHA1_80": srtp.ProtectionProfileAes128CmHmacSha1_80,
	"AES_CM_128_HMAC_SHA1_32": srtp.ProtectionProfileAes128CmHmacSha1_32,
	"AEAD_AES_128_GCM":        srtp.ProtectionProfileAeadAes128Gcm,
	"AEAD_AES_256_GCM":        srtp.ProtectionProfileAeadAes256Gcm,
}

// newContext builds a fresh SRTP context per request. Each request is self-contained, so
// replay state must not leak between them: reusing a context would make the second protect
// of the same sequence number fail for reasons that have nothing to do with the vector.
func newContext(r request) (*srtp.Context, error) {
	profile, ok := profiles[r.Profile]
	if !ok {
		return nil, fmt.Errorf("unknown protection profile %q", r.Profile)
	}

	material, err := hex.DecodeString(r.Key)
	if err != nil {
		return nil, fmt.Errorf("key is not hex: %w", err)
	}

	keyLen, err := profile.KeyLen()
	if err != nil {
		return nil, err
	}
	saltLen, err := profile.SaltLen()
	if err != nil {
		return nil, err
	}
	if len(material) != keyLen+saltLen {
		return nil, fmt.Errorf("keying material is %d bytes, profile wants %d", len(material), keyLen+saltLen)
	}

	return srtp.CreateContext(material[:keyLen], material[keyLen:], profile)
}

func handle(r request) response {
	packet, err := hex.DecodeString(r.Packet)
	if err != nil {
		return response{Error: fmt.Sprintf("packet is not hex: %v", err)}
	}

	ctx, err := newContext(r)
	if err != nil {
		return response{Error: err.Error()}
	}

	var out []byte
	switch r.Op {
	case "protect":
		out, err = ctx.EncryptRTP(nil, packet, nil)
	case "unprotect":
		out, err = ctx.DecryptRTP(nil, packet, nil)
	case "protect_rtcp":
		out, err = ctx.EncryptRTCP(nil, packet, nil)
	case "unprotect_rtcp":
		out, err = ctx.DecryptRTCP(nil, packet, nil)
	default:
		return response{Error: fmt.Sprintf("unknown op %q", r.Op)}
	}
	if err != nil {
		return response{Error: err.Error()}
	}

	return response{Result: hex.EncodeToString(out)}
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	// SRTP packets are small, but a generous buffer keeps a large vector from silently
	// truncating into a confusing parse error.
	in.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}

		var r request
		var resp response
		if err := json.Unmarshal(line, &r); err != nil {
			resp = response{Error: fmt.Sprintf("bad request: %v", err)}
		} else {
			resp = handle(r)
		}

		encoded, err := json.Marshal(resp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "refpeer-srtp: cannot encode response: %v\n", err)
			os.Exit(1)
		}
		out.Write(encoded)
		out.WriteByte('\n')
		// Flush per line: the PHP side blocks reading this response before sending the next
		// request, so buffering here would deadlock.
		out.Flush()
	}
}
