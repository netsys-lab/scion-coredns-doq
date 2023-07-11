package request

import (
	"errors"

	"github.com/miekg/dns"
)

// ScrubWriter will, when writing the message, call scrub to make it fit the client's buffer.
type ScrubWriter struct {
	dns.ResponseWriter
	req *dns.Msg // original request
}

// NewScrubWriter returns a new and initialized ScrubWriter.
func NewScrubWriter(req *dns.Msg, w dns.ResponseWriter) *ScrubWriter { return &ScrubWriter{w, req} }

func NewNoDiscardScrubWriter(req *dns.Msg, w dns.ResponseWriter) *NoDiscardScrubWriter {
	return &NoDiscardScrubWriter{w, req}
}

// WriteMsg overrides the default implementation of the underlying dns.ResponseWriter and calls
// scrub on the message m and will then write it to the client.
func (s *ScrubWriter) WriteMsg(m *dns.Msg) error {
	state := Request{Req: s.req, W: s.ResponseWriter}
	state.SizeAndDo(m)
	state.Scrub(m)
	return s.ResponseWriter.WriteMsg(m)
}

type NoDiscardScrubWriter struct {
	dns.ResponseWriter
	req *dns.Msg
}

func (ndsw *NoDiscardScrubWriter) WriteMsg(m *dns.Msg) error {

	/*	if _, ok := ndsw.ResponseWriter.(*dnsserver.DoHWriter); !ok {
			return errors.New("NoDiscardScrubWriter accepts only ResponseWriters, on which WriteMsg() can be called multiple times")
		}

		if _, ok := ndsw.ResponseWriter.(*nonwriter.Writer); ok {
			return errors.New("NoDiscardScrubWriter accepts only ResponseWriters, on which WriteMsg() can be called multiple times")
		}
	*/

	if !ndsw.SupportsMultiMsg() {
		return errors.New("NoDiscardScrubWriter accepts only ResponseWriters, on which WriteMsg() can be called multiple times")
	}

	state := Request{Req: ndsw.req, W: ndsw.ResponseWriter}
	state.SizeAndDo(m)
	replies := state.ScrubNoDiscard(m)
	//return s.ResponseWriter.WriteMsg(m)
	for _, r := range replies {
		e := ndsw.ResponseWriter.WriteMsg(r)
		if e != nil {
			return e
		}
	}
	return nil
}
