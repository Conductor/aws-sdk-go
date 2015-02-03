package aws

import (
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"
	"time"
)

func TestSignatures(t *testing.T) {
	for _, i := range []struct {
		Method  string
		URI     string
		Date    string
		Headers []struct {
			Key   string
			Value string
		}
		ExpectedAuth string
	}{
		{
			Method: "POST",
			URI:    "/",
			Date:   "Mon, 09 Sep 2011 23:36:00 GMT",
			Headers: []struct {
				Key   string
				Value string
			}{
				{Key: "ZOO", Value: "zoobar"},
				{Key: "zoo", Value: "foobar"},
				{Key: "zoo", Value: "zoobar"},
			},
			ExpectedAuth: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;zoo, Signature=54afcaaf45b331f81cd2edb974f7b824ff4dd594cbbaa945ed636b48477368ed",
		},
	} {

		date, _ := time.Parse("Mon, 02 Jan 2006 15:04:05 MST", i.Date)

		req, _ := http.NewRequest(i.Method, "http://host.foo.com"+i.URI, strings.NewReader(""))
		req.Header.Add("DATE", i.Date)
		for _, header := range i.Headers {
			req.Header.Add(header.Key, header.Value)
		}

		t.Log(">>>>>>>", req.Header.Get("Date"))

		signer := signer{
			Request:         req,
			Time:            date,
			Body:            strings.NewReader(""),
			ServiceName:     "host",
			Region:          "us-east-1",
			AccessKeyID:     "AKIDEXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
			SessionToken:    "",
			Debug:           5,
		}
		something, _ := httputil.DumpRequest(req, false)
		t.Log(string(something))
		t.Logf("%+v\n", signer)
		signer.sign()
		assertEqual(t, i.ExpectedAuth, signer.Request.Header.Get("Authorization"))

	}
}

func buildSigner(serviceName string, region string, signTime time.Time, body string) signer {
	endpoint := "https://" + serviceName + "." + region + ".amazonaws.com"
	reader := strings.NewReader(body)
	req, _ := http.NewRequest("POST", endpoint, reader)
	req.Header.Add("X-Amz-Target", "prefix.Operation")
	req.Header.Add("Content-Type", "application/x-amz-json-1.0")
	req.Header.Add("Content-Length", string(len(body)))

	return signer{
		Request:         req,
		Time:            signTime,
		Body:            reader,
		ServiceName:     serviceName,
		Region:          region,
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
		SessionToken:    "SESSION",
	}
}

func removeWS(text string) string {
	text = strings.Replace(text, " ", "", -1)
	text = strings.Replace(text, "\n", "", -1)
	text = strings.Replace(text, "\t", "", -1)
	return text
}

func assertEqual(t *testing.T, expected, given string) {
	if removeWS(expected) != removeWS(given) {
		t.Errorf("\nExpected: %s\nGiven:    %s", expected, given)
	}
}

func TestSignRequest(t *testing.T) {
	signer := buildSigner("dynamodb", "us-east-1", time.Unix(0, 0), "{}")
	signer.sign()

	expectedDate := "19700101T000000Z"
	expectedAuth := `
    AWS4-HMAC-SHA256
    Credential=AKID/19700101/us-east-1/dynamodb/aws4_request,
    SignedHeaders=content-type;host;x-amz-security-token;x-amz-target,
    Signature=4662104789134800e088b6a2bf3a1153ca7d38ecfc07a69bff2859f04900b67f
  `

	assertEqual(t, expectedAuth, signer.Request.Header.Get("Authorization"))
	assertEqual(t, expectedDate, signer.Request.Header.Get("Date"))

	expectedAuth = `
    AWS4-HMAC-SHA256
    Credential=AKID/19700101/us-east-1/s3/aws4_request,
    SignedHeaders=content-type;host;x-amz-security-token;x-amz-target,
    Signature=c41e2cb402aad3a7131cec26089809f62202fc70ccebc742afbc1ff9f032f6f4
  `

	// test for https://github.com/awslabs/aws-sdk-go/issues/82
	signer = buildSigner("s3", "us-east-1", time.Unix(0, 0), "{}")
	// use the same implementation as seen in RestClient.Do
	signer.Request.URL.Opaque = EscapePath("/bucket/path/with/equal=in/it")
	signer.sign()

	assertEqual(t, expectedAuth, signer.Request.Header.Get("Authorization"))

}

func BenchmarkSignRequest(b *testing.B) {
	signer := buildSigner("dynamodb", "us-east-1", time.Now(), "{}")
	for i := 0; i < b.N; i++ {
		signer.sign()
	}
}
