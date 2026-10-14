package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/go-chi/chi/v5"
	auth "k8s.io/api/authentication/v1"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Service, *fake.Clientset) {
	t.Helper()
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "jobs", func(a kt.Action) (bool, runtime.Object, error) {
		j := a.(kt.CreateAction).GetObject().(*batch.Job)
		j.UID = types.UID("uid-" + j.Name)
		return false, nil, nil
	})
	return &Service{Client: client, Store: storage.NewFileStorage(t.TempDir()), Config: Config{Namespace: "kms-bench", PluginNamespace: "kms-bench-plugin", E2ENamespace: "kms-bench-e2e", Image: "example/bench@sha256:" + strings.Repeat("a", 64), SourceSHA: strings.Repeat("b", 40), ServerVersion: "v1.35.9", Audience: "kms-bench-results", TransitURL: "https://transit", IngestURL: "https://ingest"}}, client
}
func spec(mode string) Spec {
	return Spec{Mode: mode, Scenario: "basic", Operation: "roundtrip", Count: 2, Concurrency: 1, Payload: 16}
}
func TestFixedTemplateReconcileCancelTimeout(t *testing.T) {
	for _, mode := range []string{"transit", "plugin", "e2e"} {
		t.Run(mode, func(t *testing.T) {
			s, c := fixture(t)
			r, e := s.Create(context.Background(), spec(mode))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Create(context.Background(), spec(mode)); !errors.Is(e, ErrConflict) {
				t.Fatal("concurrent run accepted")
			}
			j, _ := c.BatchV1().Jobs(r.Namespace).Get(context.Background(), "kms-"+r.ID, meta.GetOptions{})
			if j.Spec.Template.Spec.ServiceAccountName != r.SA || *j.Spec.BackoffLimit != 0 || *j.Spec.ActiveDeadlineSeconds != 900 {
				t.Fatal("template constraints missing")
			}
			hostPaths := 0
			for _, v := range j.Spec.Template.Spec.Volumes {
				if v.HostPath != nil {
					hostPaths++
					if v.HostPath.Path != "/run/custom-kms/kmsv2" {
						t.Fatal("unsafe host mount")
					}
				}
			}
			if (mode == "plugin" && hostPaths != 1) || (mode != "plugin" && hostPaths != 0) {
				t.Fatal("mode privilege isolation failed")
			}
			restarted := &Service{Client: c, Store: s.Store, Config: s.Config}
			if e = restarted.Reconcile(context.Background()); e != nil {
				t.Fatal(e)
			}
			list, _ := c.BatchV1().Jobs(r.Namespace).List(context.Background(), meta.ListOptions{})
			if len(list.Items) != 1 {
				t.Fatal("duplicate Job after restart")
			}
			if e = restarted.Cancel(context.Background(), r.ID); e != nil {
				t.Fatal(e)
			}
			if e = restarted.Reconcile(context.Background()); e != nil {
				t.Fatal(e)
			}
			got, _ := s.get(r.ID)
			if got.State != "cancelled" {
				t.Fatal("not cancelled")
			}
		})
	}
	s, c := fixture(t)
	r, _ := s.Create(context.Background(), spec("e2e"))
	j, _ := c.BatchV1().Jobs(r.Namespace).Get(context.Background(), "kms-"+r.ID, meta.GetOptions{})
	j.Status.Conditions = []batch.JobCondition{{Type: batch.JobFailed, Status: core.ConditionTrue, Reason: "DeadlineExceeded"}}
	c.BatchV1().Jobs(r.Namespace).UpdateStatus(context.Background(), j, meta.UpdateOptions{})
	if e := s.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := s.get(r.ID)
	if got.State != "timed_out" || got.Upload != "failed" {
		t.Fatal("deadline hidden")
	}
	router := chi.NewRouter()
	s.Mount(router)
	for _, body := range []string{`{"mode":"transit","command":["sh"]}`, `{"mode":"transit","url":"https://evil"}`, `{"mode":"transit","count":100001}`} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/api/jobs", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("untrusted template accepted")
		}
	}
}
func TestIngestBindingIdempotenceAndRecovery(t *testing.T) {
	s, c := fixture(t)
	r, e := s.Create(context.Background(), spec("transit"))
	if e != nil {
		t.Fatal(e)
	}
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "bench-pod", Namespace: r.Namespace, UID: "pod-uid", Labels: map[string]string{"kms-run-id": r.ID}, OwnerReferences: []meta.OwnerReference{{Kind: "Job", UID: types.UID(r.JobUID), Controller: ptr(true)}}}, Spec: core.PodSpec{ServiceAccountName: r.SA}}
	c.CoreV1().Pods(r.Namespace).Create(context.Background(), pod, meta.CreateOptions{})
	user := "system:serviceaccount:" + r.Namespace + ":" + r.SA
	audience := s.Config.Audience
	uid := "pod-uid"
	failReview := false
	c.PrependReactor("create", "tokenreviews", func(a kt.Action) (bool, runtime.Object, error) {
		if failReview {
			return true, nil, errors.New("unavailable")
		}
		request := a.(kt.CreateAction).GetObject().(*auth.TokenReview)
		if len(request.Spec.Audiences) != 1 || request.Spec.Audiences[0] != s.Config.Audience {
			t.Error("missing required audience")
		}
		return true, &auth.TokenReview{Status: auth.TokenReviewStatus{Authenticated: true, Audiences: []string{audience}, User: auth.UserInfo{Username: user, Extra: map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-uid": {uid}, "authentication.kubernetes.io/pod-name": {"bench-pod"}}}}}, nil
	})
	result := Result{Schema: 1, RunID: r.ID, Mode: "transit", SourceSHA: s.Config.SourceSHA, Image: s.Config.Image, ClientVersion: "go1.26.9", ServerVersion: s.Config.ServerVersion, TLS: true, Auth: "jwt-sar", Requests: 2, Success: 2, Started: time.Now().UTC(), Ended: time.Now().UTC()}
	post := func() int {
		raw, _ := json.Marshal(result)
		req := httptest.NewRequest("POST", "/api/bench/results", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer test-placeholder")
		w := httptest.NewRecorder()
		s.Ingest().ServeHTTP(w, req)
		return w.Code
	}
	audience = "wrong"
	if post() != 401 {
		t.Fatal("wrong audience accepted")
	}
	audience = s.Config.Audience
	user = "system:serviceaccount:other:sa"
	if post() != 403 {
		t.Fatal("wrong SA accepted")
	}
	user = "system:serviceaccount:" + r.Namespace + ":" + r.SA
	uid = "wrong"
	if post() != 403 {
		t.Fatal("wrong Pod UID accepted")
	}
	uid = "pod-uid"
	failReview = true
	if post() != 503 {
		t.Fatal("TokenReview failure hidden")
	}
	failReview = false
	originalID := result.RunID
	result.RunID = strings.Repeat("e", 32)
	if post() != 403 {
		t.Fatal("foreign run accepted")
	}
	result.RunID = originalID
	result.Requests = 1
	result.Success = 1
	if post() != 400 {
		t.Fatal("partial error-free run hidden as success")
	}
	result.Requests = 2
	result.Success = 2
	originalStore := s.Store
	s.Store = unavailableStorage{originalStore}
	if post() != 503 {
		t.Fatal("run storage outage hidden as authorization denial")
	}
	s.Store = originalStore
	s.Store = &failResultStorage{StorageBackend: originalStore}
	if post() != 503 {
		t.Fatal("result storage failure hidden")
	}
	s.Store = originalStore
	bound, err := s.get(r.ID)
	if err != nil || bound.PodUID != uid {
		t.Fatal("Pod binding lost before result retry")
	}
	if code := post(); code != 201 {
		t.Fatalf("valid submit: %d", code)
	}
	if post() != 201 {
		t.Fatal("retry not idempotent")
	}
	result.Errors = 1
	result.Success = 1
	if post() != 409 {
		t.Fatal("conflicting result accepted")
	}
	result.Errors = 0
	result.Success = 2
	// Crash window: result committed, run metadata still pending. Reconcile recovers it.
	saved, _ := s.get(r.ID)
	saved.Upload = "pending"
	s.save(saved)
	j, _ := c.BatchV1().Jobs(r.Namespace).Get(context.Background(), "kms-"+r.ID, meta.GetOptions{})
	j.Status.Conditions = []batch.JobCondition{{Type: batch.JobComplete, Status: core.ConditionTrue}}
	c.BatchV1().Jobs(r.Namespace).UpdateStatus(context.Background(), j, meta.UpdateOptions{})
	if e = s.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	saved, _ = s.get(r.ID)
	if saved.State != "succeeded" || saved.Upload != "stored" || saved.PodUID != uid {
		t.Fatal("restart recovery lost result")
	}
	for _, path := range []string{"/v1/sys/init", "/console", "/api/jobs"} {
		w := httptest.NewRecorder()
		s.Ingest().ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 404 {
			t.Fatal("ingest exposes management")
		}
	}
}
func TestJobCompleteWithoutUploadFails(t *testing.T) {
	s, c := fixture(t)
	r, _ := s.Create(context.Background(), spec("transit"))
	j, _ := c.BatchV1().Jobs(r.Namespace).Get(context.Background(), "kms-"+r.ID, meta.GetOptions{})
	j.Status.Conditions = []batch.JobCondition{{Type: batch.JobComplete, Status: core.ConditionTrue}}
	c.BatchV1().Jobs(r.Namespace).UpdateStatus(context.Background(), j, meta.UpdateOptions{})
	if e := s.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := s.get(r.ID)
	if got.State != "failed" {
		t.Fatal("missing upload hidden as success")
	}
}

func TestCreateResponseLostAdoptsExistingJob(t *testing.T) {
	s, c := fixture(t)
	first := true
	c.PrependReactor("create", "jobs", func(a kt.Action) (bool, runtime.Object, error) {
		if !first {
			return false, nil, nil
		}
		first = false
		j := a.(kt.CreateAction).GetObject().(*batch.Job)
		j.UID = "committed-job"
		if err := c.Tracker().Create(batch.SchemeGroupVersion.WithResource("jobs"), j, j.Namespace); err != nil {
			t.Fatal(err)
		}
		return true, nil, errors.New("response lost")
	})
	r, e := s.Create(context.Background(), spec("plugin"))
	if e == nil || r == nil {
		t.Fatal("lost response not surfaced")
	}
	if e = s.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := s.get(r.ID)
	list, _ := c.BatchV1().Jobs(r.Namespace).List(context.Background(), meta.ListOptions{})
	if got.JobUID != "committed-job" || len(list.Items) != 1 {
		t.Fatal("duplicate after response loss")
	}
}

func TestRunningJobKeepsRecordedImageAcrossAdminUpgrade(t *testing.T) {
	s, c := fixture(t)
	r, e := s.Create(context.Background(), spec("plugin"))
	if e != nil {
		t.Fatal(e)
	}
	previous := s.Config.Image
	s.Config.Image = "example/bench@sha256:" + strings.Repeat("c", 64)
	s.Config.SourceSHA = strings.Repeat("d", 40)
	if e = s.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := s.get(r.ID)
	j, _ := c.BatchV1().Jobs(r.Namespace).Get(context.Background(), "kms-"+r.ID, meta.GetOptions{})
	if got.Runtime.Image != previous || j.Spec.Template.Spec.Containers[0].Image != previous {
		t.Fatal("running Job changed on upgrade")
	}
}

type failResultStorage struct{ storage.StorageBackend }

func (s *failResultStorage) Put(key string, value []byte) error {
	if strings.HasPrefix(key, "bench/") {
		return errors.New("simulated storage full")
	}
	return s.StorageBackend.Put(key, value)
}
