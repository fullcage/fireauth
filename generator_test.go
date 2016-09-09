package fireauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/SermoDigital/jose/jws"
	"reflect"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	if gen := New("foo"); gen == nil {
		t.Fatal("generator should not be nil")
	}
}

func TestCreateTokenData(t *testing.T) {
	gen := New("foo")
	data := Data{"uid": "1"}

	token, err := gen.CreateToken(data, nil)
	if err != nil {
		t.Fatal(err)
	}

	tokenParts := strings.Split(token, TokenSep)
	if len(tokenParts) != 3 {
		t.Fatal("token is not composed correctly")
	}

	bytes, err := base64.URLEncoding.DecodeString(tokenParts[1] + "==")
	if err != nil {
		t.Fatal(err)
	}

	claim := struct {
		Version  int   `json:"v"`
		Data     Data  `json:"d"`
		IssuedAt int64 `json:"iat"`
	}{}
	if err := json.Unmarshal(bytes, &claim); err != nil {
		t.Fatal(err)
	}

	if claim.Version != Version {
		t.Fatalf("Expected: %d\nActual: %d", Version, claim.Version)
	}

	if !reflect.DeepEqual(data, claim.Data) {
		t.Fatalf("auth data is not the same.Expected: %s\nActual: %s", data, claim.Data)
	}
}

func TestCreateTokenFailure(t *testing.T) {
	if _, err := New("foo").CreateToken(nil, nil); err == nil {
		t.Fatal("CreateToken without data nor option should fail")
	}
	if _, err := New("foo").CreateToken(Data{}, nil); err == nil {
		t.Fatal("CreateToken with invalid data should fail")
	}
	ch := make(chan struct{})
	defer close(ch)
	if _, err := New("foo").CreateToken(Data{"uid": "1234", "invalid": ch}, &Option{}); err == nil {
		t.Fatal("Invalid data types should make the token creation fail")
	}
}

func TestCreateTokenAdminNoData(t *testing.T) {
	if _, err := New("foo").CreateToken(nil, &Option{Admin: true}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateTokenTooLong(t *testing.T) {
	if _, err := New("foo").CreateToken(Data{"uid": "1", "bigKey": randData(t, 1024)}, nil); err == nil {
		t.Fatal("Token too long should have failed")
	}
}

func randData(t *testing.T, size int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func TestValidate(t *testing.T) {
	if err := validate(nil, false); err != ErrNoUIDKey {
		t.Fatalf("Unexpected error. Expected: %s, Got: %v", ErrNoUIDKey, err)
	}
	if err := validate(Data{"uid": 42}, true); err != ErrUIDNotString {
		t.Fatalf("Unexpected error. Expected: %s, Got: %v", ErrUIDNotString, err)
	}
	if err := validate(Data{"uid": strings.Repeat(" ", MaxUIDLen+1)}, true); err != ErrUIDTooLong {
		t.Fatalf("Unexpected error. Expected: %s, Got: %v", ErrUIDTooLong, err)
	}
	// No uid in admin mode should not fail.
	if err := validate(Data{}, true); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateClaim(t *testing.T) {
	buf, err := generateClaim(Data{"uid": "42"}, &Option{Admin: true}, 0)
	if err != nil {
		t.Fatal(err)
	}

	if expect, got := `{"admin":true,"v":0,"d":{"uid":"42"},"iat":0}`, string(buf); expect != got {
		t.Fatalf("Unexpected claim\nExpect:\t%s\nGot:\t%s", expect, got)
	}
}

func TestSign(t *testing.T) {
	g := struct {
		key string
		in  string
		out string
	}{
		key: "you cannot see me",
		in:  "the winter is comming",
		out: "ytb5HiGUKtRhJg02DXS-serVBwbxud08FFNcx6dty78",
		// use the following code segmentation to generate the output
		// h := hmac.New(sha256.New, []byte(key))
		// h.Write([]byte(in))
		// out := encode(h.Sum(nil))
	}

	got := sign(g.in, g.key)
	if g.out != got {
		t.Fatalf("expect:%v, but got:%v", g.out, got)
	}
}

func TestCustomAuthTokenValid(t *testing.T) {
	private_key := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXJ2PtihileBbe\nmgc4tckfZNf4ZXHYevhOJs7zj9lBxD4+CBvw9WWFBhnIvLhq42DoxPFz8jYbWsh9\nj7dFp9y0TDUiIIsvTm/KNJ9mL2ttgFiOZEdS9k8N1I9dDkM2UNi7WtGP03Tm0Abz\nfrvSCJKro3lr8+tzCzfV0rtkhIaurbOy3f+iy1Bh2dQ+m6bkc4IKFHeqKPEp46mp\nagGgxergN0WIHfhcjFXkL+GspcuRw8C+AX84GZHmefyYycXY1R0DkSWMTm5q1MUs\ny5rbiCNtHW/elXoVbnlvSka3+GM9HRFXrevF+BmJHk1AziOBy49R5fgmw92/LwNQ\n3KzJl5rBAgMBAAECggEAWov0TRrKJpE0prgSA/bVTsYE8j/XOrD94P4KKIzIdRoe\ny8Jj5/OOpv4bSdTKlAlfVnbT2uT7imWZbOZXzhPIGYTc86DYkq8i8ulUkA+y2WGj\nY0Gmlq6cNIjZUONYu/ooTCj7etkWILE5y63xY4JCH8PrrNf5pe/5rp5CSRpRCB/C\nZI1Arjy7ZUPaGypAH58gakDDBWIiSCRsFX+0bt5u+J+FWebcurYQ+Y+qdpJ6cKbZ\nen0AWHQroxpWw7dWwsSriUYroKJMKLt5zM/wOJ5N4qKVwpuJX6qWB7C6JyyOZaJY\nEM5oOdMl94/Ml3gUpyfWRwV2qJkSFsvwd895hOkrhQKBgQD30WauA0SiVcHQowu/\ngbszKGaWwkoELFhPxUrtNZrQdQYBBoqft5nEA0mzY5DSoDgs4SDTMJ8HlA79XOKd\nlqCBeKWxS10zGOIxx+qWPpkulRnQek1088ZBGBxDu8V+SVfEqH+sQLEN4H9lYNe0\nRCTxrLVGcv2bezv3rpC2vKFmQwKBgQDeQegi6a73UUJV3yYGM8VBfmZjUCGb5KdH\nH8b1nc+Ty7C0z7nXU1zizN9ZZaIVMivfSt8H2W+3ikQ4FY8f7DAAQmw2JFrvKb4N\n/nnQXGIcRfO/RdM8ui88Oh7uJgZrkE9SbaWoVlhzZOv64aLqi/TZAN5UstIpNLfA\nS9s2bz/EqwKBgQCkQBELMrVR1v8PtpE5y9V0ccmVEI8YNwANVxlzIT1L/tQM5/YH\nKBxtMzStBkfdoj25WTl1YFt3HWXV/bNheY1GYt2HJglOraZ2EifkjvbeTgp/CCDA\nbDYxvLY3GoQqUJgwivGcDICNTweA/O/a1fOajrrTR7HZVJOJdRULWPismwKBgDs1\njZT3chAayrQ7rVKLqioHdVlRuJJiOJn/Ai7eqrTx15JjoFuXrrAQ6hNTuvkwk3V5\n6a6ao2Ne50uVmrpjXmpDR7aourzp/uKVf3gdlFl53TSAcoTECN9fkGvbH2y6Vhdc\ndHxC/G9JXIBKae9X95Nz4sbnmIs3qxgEXVLEElXfAoGAMgmwfSWOcdBahUvpiwOu\nJ0vJH5rmPYtBoFdd418Ynji2O0/8R9N5gDshff7ns6NBL/u1OS23fESWs4Lv09Hh\nS/ExVyxe2sa1RyDVbljLH5+aLkpWCfiNEFGcJ0kyIucPzjHJLCC6dTKh84fSTPRm\nWRRCbVUmvLnwcpIpPMhcnTc=\n-----END PRIVATE KEY-----\n"
	client_email := "test@testing.iam.gserviceaccount.com"
	userid := "tester"

	if _, err := GenerateCustomToken(userid, nil, client_email, private_key); err != nil {
		t.Fatal(err)
	}
}

func TestCustomAuthTokenInValidKey(t *testing.T) {
	private_key := "" //Key must be PEM encoded PKCS1 or PKCS8 private key
	client_email := "test@testing.iam.gserviceaccount.com"
	userid := "tester"

	if _, err := GenerateCustomToken(userid, nil, client_email, private_key); err == nil {
		t.Fatal(err)
	}
}

func TestCustomAuthTokenDeveloperClaims(t *testing.T) {
	private_key := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXJ2PtihileBbe\nmgc4tckfZNf4ZXHYevhOJs7zj9lBxD4+CBvw9WWFBhnIvLhq42DoxPFz8jYbWsh9\nj7dFp9y0TDUiIIsvTm/KNJ9mL2ttgFiOZEdS9k8N1I9dDkM2UNi7WtGP03Tm0Abz\nfrvSCJKro3lr8+tzCzfV0rtkhIaurbOy3f+iy1Bh2dQ+m6bkc4IKFHeqKPEp46mp\nagGgxergN0WIHfhcjFXkL+GspcuRw8C+AX84GZHmefyYycXY1R0DkSWMTm5q1MUs\ny5rbiCNtHW/elXoVbnlvSka3+GM9HRFXrevF+BmJHk1AziOBy49R5fgmw92/LwNQ\n3KzJl5rBAgMBAAECggEAWov0TRrKJpE0prgSA/bVTsYE8j/XOrD94P4KKIzIdRoe\ny8Jj5/OOpv4bSdTKlAlfVnbT2uT7imWZbOZXzhPIGYTc86DYkq8i8ulUkA+y2WGj\nY0Gmlq6cNIjZUONYu/ooTCj7etkWILE5y63xY4JCH8PrrNf5pe/5rp5CSRpRCB/C\nZI1Arjy7ZUPaGypAH58gakDDBWIiSCRsFX+0bt5u+J+FWebcurYQ+Y+qdpJ6cKbZ\nen0AWHQroxpWw7dWwsSriUYroKJMKLt5zM/wOJ5N4qKVwpuJX6qWB7C6JyyOZaJY\nEM5oOdMl94/Ml3gUpyfWRwV2qJkSFsvwd895hOkrhQKBgQD30WauA0SiVcHQowu/\ngbszKGaWwkoELFhPxUrtNZrQdQYBBoqft5nEA0mzY5DSoDgs4SDTMJ8HlA79XOKd\nlqCBeKWxS10zGOIxx+qWPpkulRnQek1088ZBGBxDu8V+SVfEqH+sQLEN4H9lYNe0\nRCTxrLVGcv2bezv3rpC2vKFmQwKBgQDeQegi6a73UUJV3yYGM8VBfmZjUCGb5KdH\nH8b1nc+Ty7C0z7nXU1zizN9ZZaIVMivfSt8H2W+3ikQ4FY8f7DAAQmw2JFrvKb4N\n/nnQXGIcRfO/RdM8ui88Oh7uJgZrkE9SbaWoVlhzZOv64aLqi/TZAN5UstIpNLfA\nS9s2bz/EqwKBgQCkQBELMrVR1v8PtpE5y9V0ccmVEI8YNwANVxlzIT1L/tQM5/YH\nKBxtMzStBkfdoj25WTl1YFt3HWXV/bNheY1GYt2HJglOraZ2EifkjvbeTgp/CCDA\nbDYxvLY3GoQqUJgwivGcDICNTweA/O/a1fOajrrTR7HZVJOJdRULWPismwKBgDs1\njZT3chAayrQ7rVKLqioHdVlRuJJiOJn/Ai7eqrTx15JjoFuXrrAQ6hNTuvkwk3V5\n6a6ao2Ne50uVmrpjXmpDR7aourzp/uKVf3gdlFl53TSAcoTECN9fkGvbH2y6Vhdc\ndHxC/G9JXIBKae9X95Nz4sbnmIs3qxgEXVLEElXfAoGAMgmwfSWOcdBahUvpiwOu\nJ0vJH5rmPYtBoFdd418Ynji2O0/8R9N5gDshff7ns6NBL/u1OS23fESWs4Lv09Hh\nS/ExVyxe2sa1RyDVbljLH5+aLkpWCfiNEFGcJ0kyIucPzjHJLCC6dTKh84fSTPRm\nWRRCbVUmvLnwcpIpPMhcnTc=\n-----END PRIVATE KEY-----\n"
	client_email := "test@testing.iam.gserviceaccount.com"
	userid := "tester"

	developerClaims := jws.Claims{}

	developerClaims.Set("premium_account", true)

	if _, err := GenerateCustomToken(userid, &developerClaims, client_email, private_key); err != nil {
		t.Fatal(err)
	}
}

func TestCustomAuthTokenDeveloperClaimsReserved(t *testing.T) {
	private_key := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXJ2PtihileBbe\nmgc4tckfZNf4ZXHYevhOJs7zj9lBxD4+CBvw9WWFBhnIvLhq42DoxPFz8jYbWsh9\nj7dFp9y0TDUiIIsvTm/KNJ9mL2ttgFiOZEdS9k8N1I9dDkM2UNi7WtGP03Tm0Abz\nfrvSCJKro3lr8+tzCzfV0rtkhIaurbOy3f+iy1Bh2dQ+m6bkc4IKFHeqKPEp46mp\nagGgxergN0WIHfhcjFXkL+GspcuRw8C+AX84GZHmefyYycXY1R0DkSWMTm5q1MUs\ny5rbiCNtHW/elXoVbnlvSka3+GM9HRFXrevF+BmJHk1AziOBy49R5fgmw92/LwNQ\n3KzJl5rBAgMBAAECggEAWov0TRrKJpE0prgSA/bVTsYE8j/XOrD94P4KKIzIdRoe\ny8Jj5/OOpv4bSdTKlAlfVnbT2uT7imWZbOZXzhPIGYTc86DYkq8i8ulUkA+y2WGj\nY0Gmlq6cNIjZUONYu/ooTCj7etkWILE5y63xY4JCH8PrrNf5pe/5rp5CSRpRCB/C\nZI1Arjy7ZUPaGypAH58gakDDBWIiSCRsFX+0bt5u+J+FWebcurYQ+Y+qdpJ6cKbZ\nen0AWHQroxpWw7dWwsSriUYroKJMKLt5zM/wOJ5N4qKVwpuJX6qWB7C6JyyOZaJY\nEM5oOdMl94/Ml3gUpyfWRwV2qJkSFsvwd895hOkrhQKBgQD30WauA0SiVcHQowu/\ngbszKGaWwkoELFhPxUrtNZrQdQYBBoqft5nEA0mzY5DSoDgs4SDTMJ8HlA79XOKd\nlqCBeKWxS10zGOIxx+qWPpkulRnQek1088ZBGBxDu8V+SVfEqH+sQLEN4H9lYNe0\nRCTxrLVGcv2bezv3rpC2vKFmQwKBgQDeQegi6a73UUJV3yYGM8VBfmZjUCGb5KdH\nH8b1nc+Ty7C0z7nXU1zizN9ZZaIVMivfSt8H2W+3ikQ4FY8f7DAAQmw2JFrvKb4N\n/nnQXGIcRfO/RdM8ui88Oh7uJgZrkE9SbaWoVlhzZOv64aLqi/TZAN5UstIpNLfA\nS9s2bz/EqwKBgQCkQBELMrVR1v8PtpE5y9V0ccmVEI8YNwANVxlzIT1L/tQM5/YH\nKBxtMzStBkfdoj25WTl1YFt3HWXV/bNheY1GYt2HJglOraZ2EifkjvbeTgp/CCDA\nbDYxvLY3GoQqUJgwivGcDICNTweA/O/a1fOajrrTR7HZVJOJdRULWPismwKBgDs1\njZT3chAayrQ7rVKLqioHdVlRuJJiOJn/Ai7eqrTx15JjoFuXrrAQ6hNTuvkwk3V5\n6a6ao2Ne50uVmrpjXmpDR7aourzp/uKVf3gdlFl53TSAcoTECN9fkGvbH2y6Vhdc\ndHxC/G9JXIBKae9X95Nz4sbnmIs3qxgEXVLEElXfAoGAMgmwfSWOcdBahUvpiwOu\nJ0vJH5rmPYtBoFdd418Ynji2O0/8R9N5gDshff7ns6NBL/u1OS23fESWs4Lv09Hh\nS/ExVyxe2sa1RyDVbljLH5+aLkpWCfiNEFGcJ0kyIucPzjHJLCC6dTKh84fSTPRm\nWRRCbVUmvLnwcpIpPMhcnTc=\n-----END PRIVATE KEY-----\n"
	client_email := "test@testing.iam.gserviceaccount.com"
	userid := "tester"

	developerClaims := jws.Claims{}

	developerClaims.Set("aud", "reserved")

	if _, err := GenerateCustomToken(userid, &developerClaims, client_email, private_key); err == nil {
		t.Fatal(err)
	}
}
