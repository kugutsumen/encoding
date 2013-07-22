// Copyright 2013 Bellua Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package keyvalue implements the Key-Value Form Encoding as
// specified by the OpenID Authentication 2.0 specifications.
//
//   http://openid.net/specs/openid-authentication-2_0.html#rfc.section.4.1.1
//
// Key-Value Form encoding is used for signature calculation
// and for direct responses to Relying Parties.
//
// A message in Key-Value form is a sequence of lines.
// Each line begins with a key, followed by a colon, and the value
// associated with the key. The line is terminated by a single
// newline (UCS codepoint 10, "\n").
//
// Example:
//
//       mode:error
//       error:This is an example message
package keyvalue

import (
  "bytes"
  "fmt"
  "io"
  "strings"
  "unicode"
  "unicode/utf8"
)

// Colon rune.
const colon = ':'

// Comma rune.
const comma = ','

// Newline string.
const newline = "\n"

// OpenID prefix
const prefix = "openid."


// Form maps a string key to a string value.
type Form map[string]string

// Get gets the value associated with the given key.
//
// If there are no value associated with the key,
// Get returns the empty string.
func (f Form) Get(key string) string {
  if f == nil {
    return ""
  }
  v, ok := f[key]
  if !ok || len(v) == 0 {
    return ""
  }
  return v
}

// Set sets the key to value. It replaces any existing value.
func (f Form) Set(key, value string) {
  f[key] = value
}

// Del deletes the value associated with key.
func (f Form) Del(key string) {
  delete(f, key)
}

// Validate Key-Value message.
// Additional characters, including whitespace, MUST NOT
// be added before or after the colon or newline.
//
// The message MUST be encoded in UTF-8 to produce a byte string.
func (f Form) Validate() error {
  for k, v := range f {
    // Empty value
    if len(v) == 0 {
      return fmt.Errorf("Empty value for key \"%s\"", k)
    }

    // Verify that the message line consists entirely of valid
    // UTF-8-encoded runes
    if !utf8.ValidString(k) {
      return fmt.Errorf("key must consists of valid UTF-8-encoded runes.")
    }
    if !utf8.ValidString(v) {
      return fmt.Errorf("value must consists of valid UTF-8-encoded runes.")
    }

    // key or value MUST NOT contain a newline and a key also MUST NOT contain a
    // colon.
    if strings.ContainsRune(k, '\n') || strings.ContainsRune(k, ':') {
      return fmt.Errorf("key contains a new line or colon \"%s\"", k)
    }

    // Before the colon
    if r, _ := utf8.DecodeLastRuneInString(k); unicode.IsSpace(r) {
      return fmt.Errorf("whitespace at end of key \"%s\"", k)
    }
    // After the newline
    if r, _ := utf8.DecodeRuneInString(k); unicode.IsSpace(r) {
      return fmt.Errorf("whitespace at beginning of key \"%s\"", k)
    }
    // After the colon
    if r, _ := utf8.DecodeLastRuneInString(v); unicode.IsSpace(r) {
      return fmt.Errorf("whitespace at beginning of value \"%s\"", v)
    }
    // Before the newline
    if r, _ := utf8.DecodeRuneInString(v); unicode.IsSpace(r) {
      return fmt.Errorf("whitespace at end of value \"%s\"", v)
    }
  }
  return nil
}

// String returns the Key-Value Form Encoded message.
func (f Form) String() string {
  if f == nil || len(f) == 0 {
    return ""
  }

  var buf bytes.Buffer
  var n int

  // Preallocate buffer
  for k, v := range f {
    n += len(k) + len(v) + utf8.RuneLen(colon) + len(newline)
  }
  buf.Grow(n)

  for k, v := range f {
    buf.WriteString(k)
    buf.WriteRune(colon)
    buf.WriteString(v)
    buf.WriteString(newline)
  }

  return buf.String()
}
func (f Form) Write(w io.Writer) error {
  _, err := io.WriteString(w, f.String())
  return err
}

// Signed message in key-value form.
type SignedForm struct {
  Form
  // List of fields to be signed without the "openid." prefix that the signature covers.
  Fields  []string
}

var (
  ErrMissingFields = fmt.Errorf("No fields to sign");
  ErrEmptyForm = fmt.Errorf("Form is empty or values are missing.");
)

// Comma-separated list of signed fields
func (s *SignedForm) SignedFields() string {
  if len(s.Fields) == 0 {
    return ""
  }
  var buf bytes.Buffer
  var n int

  for _, k := range s.Fields {
    n += len(k)
  }
  n += utf8.RuneLen(comma) * (len(s.Fields) - 1)
  buf.Grow(n)

  for _, k := range s.Fields {
    buf.WriteString(k)
    if buf.Len() < n {
      buf.WriteRune(comma)
    }
  }
  return buf.String()
}

// Convert the list of key/value pairs to be signed to an octet string 
// by encoding with Key-Value Form Encoding.
func (s *SignedForm) SignedString() string {
  f := s.Form 
  if f == nil || len(f) == 0 {
    return ""
  }   
  var buf bytes.Buffer
  var n int

  // Preallocate buffer
  for _, k := range s.Fields {
    v, ok := f[k]
    // The list of keys to be signed MUST be part of the message.
    if !ok || len(v) == 0 {
      return ""
    }
    n += len(prefix) + len(k) + len(v) + utf8.RuneLen(colon) + len(newline)
  }
  buf.Grow(n)

  // Iterate through the list of keys to be signed in the order they appear
  for _, k := range s.Fields {
    buf.WriteString(prefix)
    buf.WriteString(k)
    buf.WriteRune(colon)
    buf.WriteString(f.Get(k))
    buf.WriteString(newline)
  }
  return buf.String()
}
