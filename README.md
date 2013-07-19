# Package keyvalue

    import "github.com/kugutsumen/encoding/keyvalue"

## Overview

Package Message implements the Key-Value Form Encoding as specified by
the [OpenID Authentication 2.0 specifications][1].

Key-Value Form encoding is used for signature calculation and for direct
responses to Relying Parties.

A message in Key-Value form is a sequence of lines. Each line begins
with a key, followed by a colon, and the value associated with the key.
The line is terminated by a single newline (UCS codepoint 10, "\n").

Example:

    mode:error
    error:This is an example message

## Install

    go get github.com/kugutsumen/encoding/keyvalue

If this is not the first time you're "getting" the package, add `-u` 
param to get an updated version, i.e. `go get -u ...`.

## Doc

  - [keyvalue package docs][2]


[1]:	http://openid.net/specs/openid-authentication-2_0.html
[2]:  http://godoc.org/github.com/kugutsumen/encoding/keyvalue
