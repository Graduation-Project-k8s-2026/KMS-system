package jobs

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/go-chi/chi/v5"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kt "k8s.io/client-go/testing"
)

type unavailableStorage struct{ storage.StorageBackend }

func (s unavailableStorage) Get(string) ([]byte, error) {
	return nil, errors.New("backend unavailable")
}

func TestJobHTTPStatusContract(t *testing.T) {
	s, c := fixture(t)
	run, err := s.Create(context.Background(), spec("transit"))
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	s.Mount(router)
	request := func(method, id string, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, "/api/jobs/"+id, nil))
		if w.Code != want {
			t.Fatalf("%s: got %d want %d", method, w.Code, want)
		}
	}
	for _, method := range []string{"GET", "DELETE"} {
		request(method, "bad", 400)
		request(method, strings.Repeat("f", 32), 404)
	}
	request("GET", run.ID, 200)
	original := s.Store
	s.Store = unavailableStorage{original}
	request("GET", run.ID, 503)
	request("DELETE", run.ID, 503)
	s.Store = original
	c.PrependReactor("delete", "jobs", func(kt.Action) (bool, runtime.Object, error) { return true, nil, errors.New("API offline") })
	request("DELETE", run.ID, 503)
}

func TestQueuedRunningAndCancellationUploadState(t *testing.T) {
	s, c := fixture(t)
	ctx := context.Background()
	run, err := s.Create(ctx, spec("plugin"))
	if err != nil {
		t.Fatal(err)
	}
	if run.State != "queued" {
		t.Fatal("unscheduled Job marked running")
	}
	job, err := c.BatchV1().Jobs(run.Namespace).Get(ctx, "kms-"+run.ID, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	job.Status.Active = 1
	c.BatchV1().Jobs(run.Namespace).UpdateStatus(ctx, job, meta.UpdateOptions{})
	if err = s.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	current, _ := s.get(run.ID)
	if current.State != "running" {
		t.Fatal("active Job not running")
	}
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "still-running", Namespace: run.Namespace, Labels: map[string]string{"kms-run-id": run.ID}}, Status: core.PodStatus{Phase: core.PodRunning}}
	c.CoreV1().Pods(run.Namespace).Create(ctx, pod, meta.CreateOptions{})
	if err = s.Cancel(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	current, _ = s.get(run.ID)
	if current.State != "cancelling" {
		t.Fatal("cancel completed while Pod active")
	}
	c.CoreV1().Pods(run.Namespace).Delete(ctx, pod.Name, meta.DeleteOptions{})
	if err = s.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	current, _ = s.get(run.ID)
	if current.State != "cancelled" || current.Upload != "failed" {
		t.Fatal("cancelled run retained pending upload")
	}
	router := chi.NewRouter()
	s.Mount(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/jobs/"+run.ID, nil))
	if w.Code != 409 {
		t.Fatal("terminal cancellation must conflict")
	}
}
