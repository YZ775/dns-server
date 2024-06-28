package main

import (
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	upstream string
}

type dnsHandler struct {
	resolver *Resolver
}

func (r *Resolver) resolve(domain string, queryType uint16) (error, []dns.RR) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), queryType)
	m.RecursionDesired = true

	client := &dns.Client{Timeout: 5 * time.Second}
	response, _, err := client.Exchange(m, r.upstream)
	if err != nil {
		return err, nil
	}
	if response == nil {
		slog.Error("Empty response from server", "err", err)
	}
	for _, answer := range response.Answer {
		w := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)
		// slog.Info("Answer", slog.String(domain, answer.String()))
		w.Write([]byte("Answer:\n"))
		w.Write([]byte(answer.String()))
		w.Write([]byte("\n"))
		w.Flush()
	}
	return nil, response.Answer
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := &dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		slog.Info("Question", slog.String("domain", question.Name), slog.String("type", dns.TypeToString[question.Qtype]))
		err, anwser := h.resolver.resolve(question.Name, question.Qtype)
		if err != nil {
			slog.Error("Failed to resolve", "err", err)
			continue
		}
		msg.Answer = append(msg.Answer, anwser...)
	}
	w.WriteMsg(msg)
}

func StartServer() {
	resolver := &Resolver{upstream: "8.8.8.8:53"}
	handler := &dnsHandler{resolver: resolver}

	server := &dns.Server{
		Addr:      "0.0.0.0:53",
		Net:       "udp",
		Handler:   handler,
		UDPSize:   65535,
		ReusePort: true,
	}
	slog.Info("Starting server", "addr", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		slog.Error("Failed to start server", "err", err)
		os.Exit(1)
	}
}

func main() {
	StartServer()
}
