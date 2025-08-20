// Copyright 2024 Vinicius Fortuna
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin && dnssd && cgo

package sysresolver

/*
#cgo darwin LDFLAGS: -lresolv
#include <resolv.h>
#include <stdlib.h>
#include <dns_sd.h>

extern void goDNSServiceQueryRecordReply(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
	DNSServiceErrorType errorCode, char* fullname, uint16_t rrtype, uint16_t rrclass,
	uint16_t rdlen, void* rdata, uint32_t ttl, void* context);
*/
import "C"

import (
	"context"
	"fmt"
	"log"
	"runtime/cgo"
	"time"
	"unsafe"

	"github.com/Jigsaw-Code/outline-sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// resolver implements dns.Resolver via the macOS system resolver.
type resolver struct{}

// New returns a dns.Resolver that queries using the macOS system resolver.
func New() dns.Resolver {
	return &resolver{}
}

// Query performs a DNS query using the system resolver and returns the raw
// DNS message parsed into dnsmessage.Message.
// CHANGED: method on resolver, takes dnsmessage.Question, returns *dnsmessage.Message
func (r *resolver) Query(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
    cname := C.CString(q.Name.String())
    defer C.free(unsafe.Pointer(cname))

    buf := make([]byte, 1<<16)
    n := C.res_query(cname, C.C_IN, C.int(q.Type),
        (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
    if n < 0 {
        return nil, fmt.Errorf("res_query failed for %q", q.Name.String())
    }

    var msg dnsmessage.Message
    if err := msg.Unpack(buf[:n]); err != nil {
        return nil, err
    }

    return &msg, nil
}

// No longer needed because Outline SDK’s dns.Resolver expects the full
// *dnsmessage.Message, not just the answers slice.
//func Query(ctx context.Context, qname string, qtype dnsmessage.Type) (string, error) {
//	msg, err := queryAnswers(ctx, qname, qtype)
//	return formatMessage(msg), err
//}
