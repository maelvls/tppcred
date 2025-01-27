package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDotNetUnixTime_MarshalJSON(t *testing.T) {
	t.Run("UTC time", runMarshalTest(marshalTest{
		// 2012-04-23T18:25:43.511Z
		tm:       parseOrPanic("2012-04-23T18:25:43.511Z"),
		expected: `"/Date(1335205543511)/"`,
	}))
	t.Run("EST timezone", runMarshalTest(marshalTest{
		tm:       parseOrPanic("2012-04-23T13:25:43.511-05:00"),
		expected: `"/Date(1335205543511-0500)/"`,
	}))
	t.Run("CET timezone", runMarshalTest(marshalTest{
		tm:       parseOrPanic("2012-04-23T19:25:43.511+01:00"),
		expected: `"/Date(1335205543511+0100)/"`,
	}))
	t.Run("Negative time", runMarshalTest(marshalTest{
		tm:       parseOrPanic("1754-08-30T22:43:41Z"),
		expected: `"/Date(-6795364579000)/"`,
	}))
	t.Run("Negative time with +timezone", runMarshalTest(marshalTest{
		tm:       parseOrPanic("1754-08-30T23:43:41+01:00"),
		expected: `"/Date(-6795364579000+0100)/"`,
	}))
	t.Run("Negative time with -timezone", runMarshalTest(marshalTest{
		tm:       parseOrPanic("1754-08-30T17:43:41-05:00"),
		expected: `"/Date(-6795364579000-0500)/"`,
	}))
}

func TestDotNetUnixTime_UnmarshalJSON(t *testing.T) {
	t.Run("UTC time", runUnmarshallTest(unmarshalTest{
		input:       `"/Date(1335205543511)/"`,
		wantErr:     false,
		wantTimeStr: "2012-04-23T18:25:43.511Z",
	}))
	t.Run("EST timezone", runUnmarshallTest(unmarshalTest{
		input:       `"/Date(1335205543511-0500)/"`,
		wantErr:     false,
		wantTimeStr: "2012-04-23T13:25:43.511-05:00",
	}))
	t.Run("CET timezone", runUnmarshallTest(unmarshalTest{
		input:       `"/Date(1335205543511+0100)/"`,
		wantErr:     false,
		wantTimeStr: "2012-04-23T19:25:43.511+01:00",
	}))
	t.Run("Negative time", runUnmarshallTest(unmarshalTest{
		input:       `"/Date(-6795364579000)/"`,
		wantErr:     false,
		wantTimeStr: "1754-08-30T22:43:41Z",
	}))
	t.Run("Negative time with +timezone", runUnmarshallTest(unmarshalTest{
		input:       `"/Date(-6795364579000+0100)/"`,
		wantErr:     false,
		wantTimeStr: "1754-08-30T23:43:41+01:00",
	}))
	t.Run("Negative time with -timezone", runUnmarshallTest(unmarshalTest{
		input:       `"/Date(-6795364579000-0500)/"`,
		wantErr:     false,
		wantTimeStr: "1754-08-30T17:43:41-05:00",
	}))
	t.Run("Invalid format", runUnmarshallTest(unmarshalTest{
		input:   `2012-04-23`,
		wantErr: true,
	}))
	t.Run("Invalid timestamp", runUnmarshallTest(unmarshalTest{
		input:   `"/Date(invalid)/"`,
		wantErr: true,
	}))
}

type marshalTest struct {
	tm       time.Time
	expected string
}

func runMarshalTest(tc marshalTest) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		d := DotNetUnixTime(tc.tm)
		got, err := d.MarshalJSON()
		require.NoError(t, err)
		assert.Equal(t, tc.expected, string(got))
	}
}

type unmarshalTest struct {
	input       string
	wantErr     bool
	wantTimeStr string
}

func runUnmarshallTest(test unmarshalTest) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		var d DotNetUnixTime
		err := d.UnmarshalJSON([]byte(test.input))
		if test.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, test.wantTimeStr, time.Time(d).Format(time.RFC3339Nano))
	}
}

func parseOrPanic(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}
