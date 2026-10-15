package jobs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/go-chi/chi/v5"
	"io"
	auth "k8s.io/api/authentication/v1"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ErrConflict = errors.New("run conflict")
var ErrInvalidID = errors.New("invalid run ID")
var ErrNotFound = errors.New("run not found")
var idRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Config struct{ Namespace, PluginNamespace, E2ENamespace, Image, TransitURL, IngestURL, Audience, SourceSHA, ServerVersion string }
type Service struct {
	Client kubernetes.Interface
	Store  storage.StorageBackend
	Config Config
	mu     sync.Mutex
}

func (s *Service) save(r *Run) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return s.Store.Put("jobs/"+r.ID, b)
}
func (s *Service) get(id string) (*Run, error) {
	if !idRE.MatchString(id) {
		return nil, ErrInvalidID
	}
	b, e := s.Store.Get("jobs/" + id)
	if e != nil {
		return nil, e
	}
	if b == nil {
		return nil, ErrNotFound
	}
	var r Run
	e = json.Unmarshal(b, &r)
	return &r, e
}
func (s *Service) list() ([]Run, error) {
	names, e := s.Store.List("jobs/")
	if e != nil {
		return nil, e
	}
	runs := []Run{}
	for _, n := range names {
		r, e := s.get(n)
		if e != nil {
			return nil, e
		}
		runs = append(runs, *r)
	}
	return runs, nil
}
func terminal(state string) bool {
	return state == "succeeded" || state == "failed" || state == "cancelled" || state == "timed_out"
}
func (s *Service) Create(ctx context.Context, spec Spec) (*Run, error) {
	if err := s.Config.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := spec.Validate(); e != nil {
		return nil, e
	}
	runs, e := s.list()
	if e != nil {
		return nil, e
	}
	if len(runs) >= 10000 {
		return nil, errors.New("run capacity reached; archive required")
	}
	for _, r := range runs {
		if !terminal(r.State) {
			return nil, ErrConflict
		}
	}
	b := make([]byte, 16)
	if _, e = rand.Read(b); e != nil {
		return nil, e
	}
	r := &Run{Runtime: s.Config, ID: hex.EncodeToString(b), Spec: spec, State: "queued", Upload: "pending", Created: time.Now().UTC(), Namespace: s.Config.Namespace, SA: "bench-transit"}
	if spec.Mode == "plugin" {
		r.Namespace = s.Config.PluginNamespace
		r.SA = "bench-plugin"
	}
	if spec.Mode == "e2e" {
		r.Namespace = s.Config.E2ENamespace
		r.SA = "bench-e2e"
	}
	if e = s.save(r); e != nil {
		return nil, e
	}
	if e = s.ensure(ctx, r); e != nil {
		return r, e
	}
	return r, nil
}
func ptr[T any](v T) *T { return &v }
func (s *Service) template(r *Run) *batch.Job {
	args := []string{"--mode=" + r.Spec.Mode, "--scenario=basic", "--op=roundtrip", fmt.Sprint("--count=", r.Spec.Count), fmt.Sprint("--concurrency=", r.Spec.Concurrency), fmt.Sprint("--payload-bytes=", r.Spec.Payload), fmt.Sprint("--duration-seconds=", r.Spec.Duration), "--run-id=" + r.ID, "--submit-required", "--submit=" + r.Runtime.IngestURL, "--submit-ca-file=/ca/ca.crt", "--submit-token-file=/submit/token", "--ca-file=/ca/ca.crt", "--addr=" + r.Runtime.TransitURL, "--token-file=/transit/token", "--namespace=" + r.Namespace, "--kms-socket=/run/kmsv2/kms-v2.sock"}
	vols := []core.Volume{{Name: "ca", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: "kms-internal-ca"}}}}, {Name: "submit", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{Sources: []core.VolumeProjection{{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: r.Runtime.Audience, ExpirationSeconds: ptr(int64(3600)), Path: "token"}}}}}}}
	mounts := []core.VolumeMount{{Name: "ca", MountPath: "/ca", ReadOnly: true}, {Name: "submit", MountPath: "/submit", ReadOnly: true}}
	if r.Spec.Mode == "transit" {
		vols = append(vols, core.Volume{Name: "transit", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{Sources: []core.VolumeProjection{{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: "kms-system", ExpirationSeconds: ptr(int64(3600)), Path: "token"}}}}}})
		mounts = append(mounts, core.VolumeMount{Name: "transit", MountPath: "/transit", ReadOnly: true})
	}
	if r.Spec.Mode == "plugin" {
		vols = append(vols, core.Volume{Name: "kmsv2", VolumeSource: core.VolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/run/custom-kms/kmsv2", Type: ptr(core.HostPathDirectory)}}})
		mounts = append(mounts, core.VolumeMount{Name: "kmsv2", MountPath: "/run/kmsv2", ReadOnly: true})
	}
	return &batch.Job{ObjectMeta: meta.ObjectMeta{Name: "kms-" + r.ID, Namespace: r.Namespace, Labels: map[string]string{"kms-run-id": r.ID}}, Spec: batch.JobSpec{BackoffLimit: ptr(int32(0)), ActiveDeadlineSeconds: ptr(int64(900)), Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{"kms-run-id": r.ID}}, Spec: core.PodSpec{ServiceAccountName: r.SA, AutomountServiceAccountToken: ptr(r.Spec.Mode == "e2e"), RestartPolicy: core.RestartPolicyNever, SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(10001)), RunAsGroup: ptr(int64(10001)), FSGroup: ptr(int64(10001)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Volumes: vols, Containers: []core.Container{{Name: "bench", Image: r.Runtime.Image, ImagePullPolicy: core.PullNever, Args: args, VolumeMounts: mounts, Env: []core.EnvVar{{Name: "KMS_SOURCE_SHA", Value: r.Runtime.SourceSHA}, {Name: "KMS_IMAGE_DIGEST", Value: r.Runtime.Image}, {Name: "KMS_SERVER_VERSION", Value: r.Runtime.ServerVersion}}, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("1"), core.ResourceMemory: resource.MustParse("512Mi")}}}}}}}}
}
func (s *Service) ensure(ctx context.Context, r *Run) error {
	j, e := s.Client.BatchV1().Jobs(r.Namespace).Get(ctx, "kms-"+r.ID, meta.GetOptions{})
	if apierrors.IsNotFound(e) {
		if r.State == "cancelling" {
			pods, err := s.Client.CoreV1().Pods(r.Namespace).List(ctx, meta.ListOptions{LabelSelector: "kms-run-id=" + r.ID})
			if err != nil {
				return err
			}
			for _, pod := range pods.Items {
				if pod.Status.Phase != core.PodSucceeded && pod.Status.Phase != core.PodFailed {
					return s.save(r)
				}
			}
			r.State = "cancelled"
			if r.Upload != "stored" {
				r.Upload = "failed"
			}
			return s.save(r)
		}
		if r.JobUID != "" {
			r.State = "failed"
			if r.Upload != "stored" {
				r.Upload = "failed"
			}
			return s.save(r)
		}
		j, e = s.Client.BatchV1().Jobs(r.Namespace).Create(ctx, s.template(r), meta.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			j, e = s.Client.BatchV1().Jobs(r.Namespace).Get(ctx, "kms-"+r.ID, meta.GetOptions{})
		}
	}
	if e != nil {
		return e
	}
	if j.Spec.Template.Spec.ServiceAccountName != r.SA || len(j.Spec.Template.Spec.Containers) != 1 || j.Spec.Template.Spec.Containers[0].Image != r.Runtime.Image || j.Labels["kms-run-id"] != r.ID || (r.JobUID != "" && r.JobUID != string(j.UID)) {
		return ErrConflict
	}
	r.JobUID = string(j.UID)
	if r.State == "cancelling" {
		uid := j.UID
		e = s.Client.BatchV1().Jobs(r.Namespace).Delete(ctx, j.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}, PropagationPolicy: ptr(meta.DeletePropagationForeground)})
		if e != nil && !apierrors.IsNotFound(e) {
			return e
		}
		r.State = "cancelling"
		return s.save(r)
	}
	rawResult, err := s.Store.Get("bench/" + r.ID)
	if err != nil {
		return err
	}
	if rawResult != nil {
		var result Result
		if json.Unmarshal(rawResult, &result) != nil || result.Validate() != nil {
			return errors.New("stored result invalid")
		}
		r.Upload = "stored"
		r.Hash = fmt.Sprintf("%x", sha256.Sum256(rawResult))
	}
	r.State = "queued"
	if j.Status.Active > 0 || j.Status.StartTime != nil {
		r.State = "running"
	}
	for _, c := range j.Status.Conditions {
		if c.Status != core.ConditionTrue {
			continue
		}
		if c.Type == batch.JobFailed {
			r.State = "failed"
			if c.Reason == "DeadlineExceeded" {
				r.State = "timed_out"
			}
			if r.Upload != "stored" {
				r.Upload = "failed"
			}
		}
		if c.Type == batch.JobComplete {
			if r.Upload == "stored" {
				raw, e := s.Store.Get("bench/" + r.ID)
				if e != nil {
					return e
				}
				var result Result
				if json.Unmarshal(raw, &result) != nil {
					return errors.New("invalid stored result")
				}
				if result.Errors == 0 {
					r.State = "succeeded"
				} else {
					r.State = "failed"
				}
			} else {
				r.State = "failed"
				r.Upload = "failed"
			}
		}
	}
	return s.save(r)
}
func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, e := s.list()
	if e != nil {
		return e
	}
	for i := range runs {
		r := &runs[i]
		if terminal(r.State) {
			continue
		}
		if e = s.ensure(ctx, r); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) Cancel(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.get(id)
	if e != nil {
		return e
	}
	if terminal(r.State) {
		return ErrConflict
	}
	r.State = "cancelling"
	if e = s.save(r); e != nil {
		return e
	}
	return s.ensure(ctx, r)
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (s *Service) Mount(r chi.Router) {
	r.Post("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		var spec Spec
		if decode(r, &spec) != nil || spec.Validate() != nil {
			http.Error(w, "invalid job parameters", 400)
			return
		}
		run, e := s.Create(r.Context(), spec)
		if e != nil {
			code := 503
			if errors.Is(e, ErrConflict) {
				code = 409
			}
			http.Error(w, "job creation pending or rejected", code)
			return
		}
		respond(w, 201, run)
	})
	r.Get("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		runs, e := s.list()
		if e != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		respond(w, 200, runs)
	})
	r.Get("/api/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		run, e := s.get(chi.URLParam(r, "id"))
		if e != nil {
			http.Error(w, "run unavailable", runErrorStatus(e))
			return
		}
		respond(w, 200, run)
	})
	r.Delete("/api/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		e := s.Cancel(r.Context(), chi.URLParam(r, "id"))
		if e != nil {
			http.Error(w, "cancel pending or rejected", runErrorStatus(e))
			return
		}
		w.WriteHeader(204)
	})
	r.Get("/api/bench/results/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if !idRE.MatchString(id) {
			http.Error(w, "invalid ID", 400)
			return
		}
		raw, e := s.Store.Get("bench/" + id)
		if e != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		if raw == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
}

// Ingest has exactly one route. TokenReview credentials are never persisted.
func (s *Service) Ingest() http.Handler {
	r := chi.NewRouter()
	r.Post("/api/bench/results", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || token == r.Header.Get("Authorization") {
			http.Error(w, "token required", 401)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		review, e := s.Client.AuthenticationV1().TokenReviews().Create(ctx, &auth.TokenReview{Spec: auth.TokenReviewSpec{Token: token, Audiences: []string{s.Config.Audience}}}, meta.CreateOptions{})
		if e != nil {
			http.Error(w, "authentication unavailable", 503)
			return
		}
		audience := false
		for _, a := range review.Status.Audiences {
			if a == s.Config.Audience {
				audience = true
			}
		}
		if !review.Status.Authenticated || !audience {
			http.Error(w, "invalid token", 401)
			return
		}
		audit.SetSubject(r, review.Status.User.Username)
		var result Result
		if decode(r, &result) != nil || result.Validate() != nil {
			http.Error(w, "invalid result", 400)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		run, e := s.get(result.RunID)
		if e != nil {
			code := runErrorStatus(e)
			if code == 404 {
				code = 403
			}
			http.Error(w, "run denied or unavailable", code)
			return
		}
		if review.Status.User.Username != "system:serviceaccount:"+run.Namespace+":"+run.SA || result.Mode != run.Spec.Mode {
			http.Error(w, "identity or mode denied", 403)
			return
		}
		podUID := review.Status.User.Extra["authentication.kubernetes.io/pod-uid"]
		podName := review.Status.User.Extra["authentication.kubernetes.io/pod-name"]
		if len(podUID) != 1 || len(podName) != 1 {
			http.Error(w, "bound pod required", 403)
			return
		}
		pod, e := s.Client.CoreV1().Pods(run.Namespace).Get(ctx, podName[0], meta.GetOptions{})
		if e != nil {
			http.Error(w, "pod verification unavailable", 503)
			return
		}
		owned := false
		for _, owner := range pod.OwnerReferences {
			if owner.UID == types.UID(run.JobUID) && owner.Kind == "Job" && owner.Controller != nil && *owner.Controller {
				owned = true
			}
		}
		if (run.PodUID != "" && run.PodUID != podUID[0]) || string(pod.UID) != podUID[0] || pod.Spec.ServiceAccountName != run.SA || !owned || pod.Labels["kms-run-id"] != run.ID || pod.DeletionTimestamp != nil {
			http.Error(w, "pod binding denied", 403)
			return
		}
		run.PodUID = podUID[0]
		result.Started = result.Started.UTC()
		result.Ended = result.Ended.UTC()
		raw, _ := json.Marshal(result)
		hash := fmt.Sprintf("%x", sha256.Sum256(raw))
		existing, e := s.Store.Get("bench/" + run.ID)
		if e != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		if existing != nil {
			if fmt.Sprintf("%x", sha256.Sum256(existing)) != hash {
				http.Error(w, "result conflict", 409)
				return
			}
			run.Upload = "stored"
			run.Hash = hash
			if e = s.save(run); e != nil {
				http.Error(w, "storage unavailable", 503)
				return
			}
			respond(w, 201, map[string]string{"id": run.ID})
			return
		}
		if terminal(run.State) || run.State == "cancelling" {
			http.Error(w, "run closed", 409)
			return
		}
		if result.Requests > run.Spec.Count || (run.Spec.Duration == 0 && result.Errors == 0 && result.Requests != run.Spec.Count) {
			http.Error(w, "result exceeds run budget", 400)
			return
		}
		if result.SourceSHA != run.Runtime.SourceSHA || result.Image != run.Runtime.Image || result.ServerVersion != run.Runtime.ServerVersion || result.Started.Before(run.Created.Add(-time.Minute)) || result.Ended.After(time.Now().Add(time.Minute)) {
			http.Error(w, "provenance mismatch", 400)
			return
		}
		// Persist the authenticated Pod binding before committing its result.
		// Reconciliation can recover a result write even if the final metadata save fails.
		if e = s.save(run); e != nil {
			http.Error(w, "run storage unavailable", 503)
			return
		}
		if e = s.Store.Put("bench/"+run.ID, raw); e != nil {
			http.Error(w, "result storage unavailable", 503)
			return
		}
		run.Upload = "stored"
		run.Hash = hash
		if e = s.save(run); e != nil {
			http.Error(w, "run storage unavailable", 503)
			return
		}
		respond(w, 201, map[string]string{"id": run.ID})
	})
	return r
}

func (c Config) Validate() error {
	if !imageRE.MatchString(c.Image) || !shaRE.MatchString(c.SourceSHA) || !versionRE.MatchString(c.ServerVersion) {
		return errors.New("pinned image and source/server versions required")
	}
	if c.Namespace == "" || c.PluginNamespace == "" || c.E2ENamespace != "kms-bench-e2e" || c.Namespace == c.PluginNamespace || c.Namespace == c.E2ENamespace || c.PluginNamespace == c.E2ENamespace {
		return errors.New("three separate benchmark namespaces required")
	}
	if c.Audience != "kms-bench-results" {
		return errors.New("dedicated result audience required")
	}
	for _, raw := range []string{c.TransitURL, c.IngestURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return errors.New("fixed HTTPS origins required")
		}
	}
	return nil
}

func runErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrInvalidID):
		return http.StatusBadRequest
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}
