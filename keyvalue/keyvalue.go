// Copyright 2013 Bellua Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package keyvalue implements the Key-Value Form Encoding as
// specified by the OpenID Authentication 2.0 specifications.
//
//   http://openid.net/specs/openid-authentication-2_0.html#anchor4
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
  "strings"
  "unicode"
  "unicode/utf8"
)

// Colon rune.
const colon = ':'

// Newline string.
const newline = "\n"

// Message maps a string key to a string value.
type Message map[string]string

// Get gets the value associated with the given key.
//
// If there are no value associated with the key,
// Get returns the empty string.
func (m Message) Get(key string) string {
  if m == nil {
    return ""
  }
  v, ok := m[key]
  if !ok || len(v) == 0 {
    return ""
  }
  return v
}

// Set sets the key to value. It replaces any existing value.
func (m Message) Set(key, value string) {
  m[key] = value
}

// Del deletes the value associated with key.
func (m Message) Del(key string) {
  delete(m, key)
}

// Validate Key-Value message
// Additional characters, including whitespace, MUST NOT
// be added before or after the colon or newline.
//
// The message MUST be encoded in UTF-8 to produce a byte string.
func (m Message) Validate() error {
  for k, v := range m {
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
func (v Message) String() string {
  if v == nil || len(v) == 0 {
    return ""
  }

  var buf bytes.Buffer
  var n int

  // Preallocate buffer
  for k, v := range v {
    n += len(k) + len(v) + utf8.RuneLen(colon) + len(newline)
  }
  buf.Grow(n)

  for k, v := range v {
    buf.WriteString(k)
    buf.WriteRune(colon)
    buf.WriteString(v)
    buf.WriteString(newline)
  }

  return buf.String()
}
