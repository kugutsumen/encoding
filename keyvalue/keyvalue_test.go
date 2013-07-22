package keyvalue

import (
  "testing"
)

type FormTest struct {
  f   Form
  out string
}

var FormTests = []FormTest{
  // Valid Form
  {Form{"foo": "bar"}, "foo:bar\n"},
  // nil Form
  {nil, ""},
  // empty Form
  {Form{}, ""},
}

func TestFormString(t *testing.T) {
  for _, tt := range FormTests {
    if s := tt.f.String(); s != tt.out {
      t.Errorf(`%+v.String() = %s, want %s`, tt.f, s, tt.out)
    }
  }
}

type SignedFormTest struct {
  f   *SignedForm
  // keys []string
  out string
}

var SignedFormTests = []SignedFormTest{
  // Valid Form
  {&SignedForm{Form{"foo": "bar"}, []string{"foo",}}, prefix + "foo:bar\n"},
  {&SignedForm{Form{"foo": "bar", "santa": "banta"}, 
      []string{"santa", "foo"}}, prefix + "santa:banta\n" + prefix + "foo:bar\n" },
  //    prefix + "santa:banta\n" + prefix + "foo:bar\n"},
}

func TestFormSignedString(t *testing.T) {
  for _, tt := range SignedFormTests {
    if s := tt.f.SignedString(); s != tt.out {
      t.Errorf(`%+v.SignedString() = %s, want %s`, tt.f, s, tt.out)
    }
  }
}

var SignedFieldsTests = []SignedFormTest{
  // Valid Form
  {&SignedForm{Form{"foo": "bar"}, []string{"foo",}}, "foo"},
  {&SignedForm{Form{"foo": "bar", "santa": "banta"}, 
      []string{"santa", "foo"}}, "santa,foo"}, 
  //    prefix + "santa:banta\n" + prefix + "foo:bar\n"},
}

func TestFormSignedFields(t *testing.T) {
  for _, tt := range SignedFieldsTests {
    if s := tt.f.SignedFields(); s != tt.out {
      t.Errorf(`%+v.SignedFields() = %s, want %s`, tt.f, s, tt.out)
    }
  }
}


type FormValidateTest struct {
  f          Form
  expectedOk bool
}

var FormValidateTests = []FormValidateTest{
  // Valid Form
  {Form{"foo": "bar"}, true},
  // Empty Form
  {Form{}, true},
  // Key contains colon
  {Form{"f" + string(colon) + "oo": "bar"}, false},
  // Key contains newline
  {Form{"f" + string(newline) + "oo": "bar"}, false},
  // Space after newline
  {Form{" foo": "bar"}, false},
  // Space before colon
  {Form{"foo ": "bar"}, false},
  // Space after colon
  {Form{"foo": " bar"}, false},
  // Space before newline
  {Form{"foo": "bar "}, false},
  // Non UTF-8 key
  {Form{"foo\xff": "bar"}, false},
  // Non UTF-8 value
  {Form{"foo": "ba\xfer"}, false},
}

func TestFormValidateString(t *testing.T) {
  for _, tt := range FormValidateTests {
    err := tt.f.Validate()
    ok := err == nil
    if ok != tt.expectedOk {
      t.Errorf("Expected valid =%v for %v; got %v (%v)", tt.expectedOk, tt.f, ok, err)
    }
  }
}
