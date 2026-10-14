package main

import (
	"context"
	"errors"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/demo"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/security"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	for _, k := range []string{"DEMO_TRANSIT_URL", "DEMO_CA_FILE", "DEMO_TOKEN_FILE", "DEMO_PUBLIC_ORIGIN", "DEMO_TLS_CERT", "DEMO_TLS_KEY"} {
		if os.Getenv(k) == "" {
			log.Fatal(k + " required")
		}
	}
	if !strings.HasPrefix(os.Getenv("DEMO_TRANSIT_URL"), "https://") || !strings.HasPrefix(os.Getenv("DEMO_PUBLIC_ORIGIN"), "https://") {
		log.Fatal("HTTPS required")
	}
	client, e := security.TLSClient(os.Getenv("DEMO_CA_FILE"))
	if e != nil {
		log.Fatal("CA unavailable")
	}
	client.Transport = security.FileToken{Base: client.Transport, Path: os.Getenv("DEMO_TOKEN_FILE")}
	h := demo.Handler(bench.NewClient(os.Getenv("DEMO_TRANSIT_URL"), "", client), os.Getenv("DEMO_PUBLIC_ORIGIN"))
	srv := security.Server(":8443", h)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	if e = srv.ListenAndServeTLS(os.Getenv("DEMO_TLS_CERT"), os.Getenv("DEMO_TLS_KEY")); e != nil && !errors.Is(e, http.ErrServerClosed) {
		log.Fatal("demo HTTPS listener failed")
	}
}
