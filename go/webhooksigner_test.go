package webhooksigner

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorsFile struct {
	HMAC []struct {
		Name            string `json:"name"`
		KeyHex          string `json:"key_hex"`
		Key             string `json:"key"`
		Payload         string `json:"payload"`
		PayloadHex      string `json:"payload_hex"`
		PayloadEncoding string `json:"payload_encoding"`
		SignatureHex    string `json:"signature_hex"`
	} `json:"hmac_sha256"`
	Ed25519 []struct {
		Name            string `json:"name"`
		SecretKeyHex    string `json:"secret_key_hex"`
		PublicKeyHex    string `json:"public_key_hex"`
		Payload         string `json:"payload"`
		PayloadHex      string `json:"payload_hex"`
		PayloadEncoding string `json:"payload_encoding"`
		SignatureHex    string `json:"signature_hex"`
	} `json:"ed25519"`
	Stripe []struct {
		Name             string `json:"name"`
		Secret           string `json:"secret"`
		Payload          string `json:"payload"`
		Header           string `json:"header"`
		Now              int64  `json:"now"`
		ToleranceSeconds int    `json:"tolerance_seconds"`
		ExpectValid      bool   `json:"expect_valid"`
	} `json:"header_stripe_style"`
	Github []struct {
		Name        string `json:"name"`
		Secret      string `json:"secret"`
		Payload     string `json:"payload"`
		Header      string `json:"header"`
		ExpectValid bool   `json:"expect_valid"`
	} `json:"header_github_style"`
	CheckSecret []struct {
		Secret      string  `json:"secret"`
		ExpectOK    bool    `json:"expect_ok"`
		ExpectIssue *string `json:"expect_issue"`
	} `json:"check_secret"`
}

func loadVectors(t *testing.T) vectorsFile {
	t.Helper()
	raw, err := os.ReadFile("../vectors/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func vecPayload(enc, payload, payloadHex string) []byte {
	if enc == "hex" {
		b, _ := hex.DecodeString(payloadHex)
		return b
	}
	return []byte(payload)
}

func vecSecret(keyHex, key string) []byte {
	if keyHex != "" {
		b, _ := hex.DecodeString(keyHex)
		return b
	}
	return []byte(key)
}

func TestHMACVectorsSign(t *testing.T) {
	for _, v := range loadVectors(t).HMAC {
		got := SignHMAC(vecSecret(v.KeyHex, v.Key), vecPayload(v.PayloadEncoding, v.Payload, v.PayloadHex))
		if got != v.SignatureHex {
			t.Errorf("%s: got %s want %s", v.Name, got, v.SignatureHex)
		}
	}
}

func TestHMACVectorsVerify(t *testing.T) {
	for _, v := range loadVectors(t).HMAC {
		if !VerifyHMAC(vecSecret(v.KeyHex, v.Key), vecPayload(v.PayloadEncoding, v.Payload, v.PayloadHex), v.SignatureHex) {
			t.Errorf("%s: valid signature rejected", v.Name)
		}
		if VerifyHMAC([]byte("not-the-right-secret-key-value"), vecPayload(v.PayloadEncoding, v.Payload, v.PayloadHex), v.SignatureHex) {
			t.Errorf("%s: wrong secret accepted", v.Name)
		}
	}
}

func TestEd25519VectorsVerify(t *testing.T) {
	for _, v := range loadVectors(t).Ed25519 {
		payload := vecPayload(v.PayloadEncoding, v.Payload, v.PayloadHex)
		if !VerifyEd25519(v.PublicKeyHex, payload, v.SignatureHex) {
			t.Errorf("%s: valid signature rejected", v.Name)
		}
		sig, err := SignEd25519(v.SecretKeyHex, payload)
		if err != nil {
			t.Fatalf("%s: sign: %v", v.Name, err)
		}
		if sig != v.SignatureHex {
			t.Errorf("%s: sign mismatch", v.Name)
		}
	}
}

func TestEd25519Tampered(t *testing.T) {
	v := loadVectors(t).Ed25519[2]
	if VerifyEd25519(v.PublicKeyHex, []byte(v.Payload+"x"), v.SignatureHex) {
		t.Error("tampered payload accepted")
	}
	if VerifyEd25519("abcd", []byte("payload"), "ef01") {
		t.Error("bad key accepted")
	}
	if VerifyEd25519(v.PublicKeyHex, []byte("x"), "zz-not-hex") {
		t.Error("bad signature accepted")
	}
}

func TestStripeHeaderVectors(t *testing.T) {
	for _, v := range loadVectors(t).Stripe {
		got := VerifyStripeHeader([]byte(v.Secret), []byte(v.Payload), v.Header, StripeHeaderOptions{
			ToleranceSeconds: v.ToleranceSeconds,
			NowUnix:          v.Now,
		})
		if got != v.ExpectValid {
			t.Errorf("%s: got %v want %v", v.Name, got, v.ExpectValid)
		}
	}
	if VerifyStripeHeader([]byte("s"), []byte("p"), "", StripeHeaderOptions{}) {
		t.Error("empty header accepted")
	}
	if VerifyStripeHeader([]byte("s"), []byte("p"), "t=notanumber,v1=abc", StripeHeaderOptions{}) {
		t.Error("bad timestamp accepted")
	}
}

func TestGithubHeaderVectors(t *testing.T) {
	for _, v := range loadVectors(t).Github {
		got := VerifyGithubHeader([]byte(v.Secret), []byte(v.Payload), v.Header)
		if got != v.ExpectValid {
			t.Errorf("%s: got %v want %v", v.Name, got, v.ExpectValid)
		}
	}
	if VerifyGithubHeader([]byte("s"), []byte("p"), "sha1=deadbeef") {
		t.Error("sha1 accepted")
	}
	if VerifyGithubHeader([]byte("s"), []byte("p"), "garbage") {
		t.Error("garbage accepted")
	}
}

func TestCheckSecretVectors(t *testing.T) {
	for _, v := range loadVectors(t).CheckSecret {
		r := CheckSecret(v.Secret)
		if r.OK != v.ExpectOK {
			t.Errorf("%q: ok=%v want %v", v.Secret, r.OK, v.ExpectOK)
		}
		if v.ExpectIssue != nil {
			found := false
			for _, i := range r.Issues {
				if i == *v.ExpectIssue {
					found = true
				}
			}
			if !found {
				t.Errorf("%q: missing issue %s", v.Secret, *v.ExpectIssue)
			}
		} else if len(r.Issues) != 0 {
			t.Errorf("%q: unexpected issues %v", v.Secret, r.Issues)
		}
	}
}

func TestRegistry(t *testing.T) {
	RegisterAlgorithm("hmac-sha256-any", func(secret, payload []byte, sig string) bool {
		return VerifyHMAC(secret, payload, sig)
	})
	sig := SignHMAC([]byte("k"), []byte("payload"))
	if !VerifyWithAlgorithm("hmac-sha256-any", []byte("k"), []byte("payload"), sig) {
		t.Error("registered algorithm failed")
	}
	if VerifyWithAlgorithm("unknown-algo", []byte("k"), []byte("payload"), sig) {
		t.Error("unknown algorithm accepted")
	}
	found := false
	for _, n := range ListAlgorithms() {
		if n == "hmac-sha256-any" {
			found = true
		}
	}
	if !found {
		t.Error("algorithm not listed")
	}
}
