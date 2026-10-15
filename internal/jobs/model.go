package jobs

import (
	"errors"
	"regexp"
	"time"
)

type Spec struct {
	Mode        string `json:"mode"`
	Scenario    string `json:"scenario"`
	Operation   string `json:"op"`
	Count       int    `json:"count"`
	Concurrency int    `json:"concurrency"`
	Payload     int    `json:"payload_bytes"`
	Duration    int    `json:"duration_seconds"`
}

func (s Spec) Validate() error {
	if (s.Mode != "transit" && s.Mode != "plugin" && s.Mode != "e2e") || s.Scenario != "basic" || (s.Operation != "roundtrip") || s.Count < 1 || s.Count > 100000 || s.Concurrency < 1 || s.Concurrency > 32 || s.Payload < 1 || s.Payload > 1<<20 || s.Duration < 0 || s.Duration > 300 {
		return errors.New("invalid fixed benchmark parameters")
	}
	return nil
}

type Run struct {
	Runtime   Config    `json:"runtime"`
	PodUID    string    `json:"submitter_pod_uid,omitempty"`
	ID        string    `json:"run_id"`
	Spec      Spec      `json:"spec"`
	Namespace string    `json:"namespace"`
	SA        string    `json:"service_account"`
	JobUID    string    `json:"job_uid"`
	State     string    `json:"state"`
	Upload    string    `json:"upload"`
	Hash      string    `json:"result_hash,omitempty"`
	Created   time.Time `json:"created_at"`
}
type Result struct {
	Schema        int       `json:"schema_version"`
	RunID         string    `json:"run_id"`
	Mode          string    `json:"mode"`
	SourceSHA     string    `json:"source_sha"`
	Image         string    `json:"image_digest"`
	ClientVersion string    `json:"client_version"`
	ServerVersion string    `json:"server_version"`
	TLS           bool      `json:"tls"`
	Auth          string    `json:"auth"`
	Retries       int       `json:"retries"`
	Requests      int       `json:"requests"`
	Success       int       `json:"success"`
	Errors        int       `json:"errors"`
	Started       time.Time `json:"started_at"`
	Ended         time.Time `json:"ended_at"`
	P50           float64   `json:"p50_seconds"`
	P95           float64   `json:"p95_seconds"`
	P99           float64   `json:"p99_seconds"`
}

var versionRE = regexp.MustCompile(`^[a-zA-Z0-9._+-]{1,64}$`)
var shaRE = regexp.MustCompile(`^[a-f0-9]{40}$`)
var imageRE = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)

func (r Result) Validate() error {
	if !shaRE.MatchString(r.SourceSHA) || !imageRE.MatchString(r.Image) || !versionRE.MatchString(r.ClientVersion) || !versionRE.MatchString(r.ServerVersion) || r.TLS != (r.Mode != "plugin") || r.Auth != map[string]string{"transit": "jwt-sar", "plugin": "uds", "e2e": "kubernetes"}[r.Mode] {
		return errors.New("invalid result provenance")
	}

	if r.Schema != 1 || r.RunID == "" || (r.Mode != "transit" && r.Mode != "plugin" && r.Mode != "e2e") || r.Requests < 1 || r.Success < 0 || r.Errors < 0 || r.Success+r.Errors != r.Requests || r.Requests > 100000 || r.Ended.Before(r.Started) || r.Started.IsZero() || r.Ended.Sub(r.Started) > 900*time.Second || r.P50 < 0 || r.P95 < r.P50 || r.P99 < r.P95 || r.Retries != 0 {
		return errors.New("invalid result schema")
	}
	return nil
}
