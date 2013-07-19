package keyvalue

import (
  "testing"
)

type MessageTest struct {
  m   Message
  out string
}

var MessageTests = []MessageTest{
  // Valid Message
  {Message{"foo": "bar"}, "foo:bar\n"},
  // nil Message
  {nil, ""},
  // empty Message
  {Message{}, ""},
}

func TestMessageString(t *testing.T) {
  for _, tt := range MessageTests {
    if s := tt.m.String(); s != tt.out {
      t.Errorf(`%+v.String() = %s, want %s`, tt.m, s, tt.out)
    }
  }
}

type MessageValidateTest struct {
  m          Message
  expectedOk bool
}

var MessageValidateTests = []MessageValidateTest{
  // Valid Form
  {Message{"foo": "bar"}, true},
  // Empty Form
  {Message{}, true},
  // Key contains colon
  {Message{"f" + string(colon) + "oo": "bar"}, false},
  // Key contains newline
  {Message{"f" + string(newline) + "oo": "bar"}, false},
  // Space after newline
  {Message{" foo": "bar"}, false},
  // Space before colon
  {Message{"foo ": "bar"}, false},
  // Space after colon
  {Message{"foo": " bar"}, false},
  // Space before newline
  {Message{"foo": "bar "}, false},
  // Non UTF-8 key
  {Message{"foo\xff": "bar"}, false},
  // Non UTF-8 value
  {Message{"foo": "ba\xfer"}, false},
}

func TestMessageValidateString(t *testing.T) {
  for _, tt := range MessageValidateTests {
    err := tt.m.Validate()
    ok := err == nil
    if ok != tt.expectedOk {
      t.Errorf("Expected valid =%v for %v; got %v (%v)", tt.expectedOk, tt.m, ok, err)
    }
  }
}
