package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

//go:embed ui
var uiFS embed.FS

// 환경변수 이름과 기본값.
const (
	EnvMetricsURL      = "ADMIN_API_METRICS_URL"
	EnvMetricsInterval = "ADMIN_API_METRICS_INTERVAL"
	EnvMetricsWindow   = "ADMIN_API_METRICS_WINDOW"
	EnvBenchDir        = "ADMIN_API_BENCH_DIR"

	DefaultMetricsURL      = "http://127.0.0.1:9100/metrics"
	DefaultMetricsInterval = 5  // 초
	DefaultMetricsWindow   = 15 // 분
	// DefaultBenchDir은 KMS_DATA_DIR 기본값(./data)과 겹치지 않는 곳이다 —
	// 같은 디렉터리에서 두 프로세스를 띄워도 벤치 결과가 키 저장소에 섞이지 않는다.
	DefaultBenchDir = "./admin-data/bench"

	defaultTrafficWindow = 5 * time.Minute
	minTrafficWindow     = 30 * time.Second
)

// Config는 대시보드 설정이다.
type Config struct {
	MetricsURL      string // 빈 값이면 메트릭 수집 끔
	MetricsInterval time.Duration
	MetricsWindow   time.Duration
	BenchDir        string
	SocketPath      string // 메트릭을 못 얻을 때 sealed/keys를 가져올 admin.sock
}

// ConfigFromEnv는 lookup(os.LookupEnv 형태)으로 환경변수를 읽어 Config를 만든다.
// ADMIN_API_METRICS_URL은 "설정했지만 빈 값"이면 수집을 끄고, 아예 없으면 기본값을 쓴다.
func ConfigFromEnv(lookup func(string) (string, bool), socketPath string) (Config, error) {
	cfg := Config{
		MetricsURL:      DefaultMetricsURL,
		MetricsInterval: DefaultMetricsInterval * time.Second,
		MetricsWindow:   DefaultMetricsWindow * time.Minute,
		BenchDir:        DefaultBenchDir,
		SocketPath:      socketPath,
	}
	if v, ok := lookup(EnvMetricsURL); ok {
		cfg.MetricsURL = v
	}
	if v, ok := lookup(EnvBenchDir); ok && v != "" {
		cfg.BenchDir = v
	}
	if v, ok := lookup(EnvMetricsInterval); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return cfg, fmt.Errorf("%s must be a positive integer (seconds), got %q", EnvMetricsInterval, v)
		}
		cfg.MetricsInterval = time.Duration(n) * time.Second
	}
	if v, ok := lookup(EnvMetricsWindow); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return cfg, fmt.Errorf("%s must be a positive integer (minutes), got %q", EnvMetricsWindow, v)
		}
		cfg.MetricsWindow = time.Duration(n) * time.Minute
	}
	return cfg, nil
}

// Service는 대시보드 화면과 JSON API를 묶는다.
type Service struct {
	Collector *Collector
	Bench     *BenchStore
	sock      *socketClient
}

// NewService는 설정대로 수집기와 저장소를 만든다. 수집은 Run으로 시작한다.
func NewService(cfg Config) (*Service, error) {
	store, err := NewBenchStore(cfg.BenchDir, DefaultMaxBenchBytes, DefaultMaxBenchFiles)
	if err != nil {
		return nil, err
	}
	s := &Service{
		Collector: NewCollector(cfg.MetricsURL, cfg.MetricsInterval, cfg.MetricsWindow, nil),
		Bench:     store,
	}
	if cfg.SocketPath != "" {
		s.sock = newSocketClient(cfg.SocketPath)
	}
	return s, nil
}

// Run은 메트릭 수집 루프를 ctx가 끝날 때까지 돌린다(수집이 꺼져 있으면 즉시 반환).
func (s *Service) Run(ctx context.Context) { s.Collector.Run(ctx) }

// Mount는 대시보드 경로를 r에 등록한다.
func (s *Service) Mount(r chi.Router) {
	r.Get("/dashboard", s.handlePage)
	r.Handle("/dashboard/static/*", http.StripPrefix("/dashboard/static/", http.FileServerFS(mustSub("ui/static"))))

	r.Get("/api/dashboard/status", s.handleStatus)
	r.Get("/api/dashboard/traffic", s.handleTraffic)

	r.Post("/api/bench/results", s.handleBenchPost)
	r.Get("/api/bench/results", s.handleBenchList)
	r.Get("/api/bench/results/{id}", s.handleBenchGet)
	r.Delete("/api/bench/results/{id}", s.handleBenchDelete)
}

func mustSub(dir string) fs.FS {
	sub, err := fs.Sub(uiFS, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

func (s *Service) handlePage(w http.ResponseWriter, r *http.Request) {
	page, err := uiFS.ReadFile("ui/dashboard.html")
	if err != nil {
		http.Error(w, "dashboard page missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, buildStatus(r.Context(), s.Collector, s.sock))
}

func (s *Service) handleTraffic(w http.ResponseWriter, r *http.Request) {
	window := defaultTrafficWindow
	if max := s.Collector.Window(); window > max && max >= minTrafficWindow {
		window = max // 보관 길이가 기본값보다 짧으면 있는 만큼만 보여준다
	}
	if v := r.URL.Query().Get("window"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "window must be a duration such as 30s, 5m or 15m")
			return
		}
		window = d
	}
	if max := s.Collector.Window(); window < minTrafficWindow || (max > 0 && window > max) {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("window must be between %s and %s", minTrafficWindow, s.Collector.Window()))
		return
	}
	step := s.Collector.interval
	// 구간의 첫 점을 계산할 기준 샘플 하나를 더 포함한다.
	samples := s.Collector.samplesSince(time.Now().Add(-window - step))
	writeJSON(w, http.StatusOK, computeTraffic(samples, window, step))
}

func (s *Service) handleBenchPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.Bench.maxBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", s.Bench.maxBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	meta, err := s.Bench.Put(raw)
	var verr *ValidationError
	switch {
	case errors.As(err, &verr):
		writeError(w, http.StatusBadRequest, verr.Msg)
	case errors.Is(err, ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "bench result too large")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "cannot store bench result")
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"id": meta.ID, "runs": meta.Conditions})
	}
}

func (s *Service) handleBenchList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Bench.List())
}

func (s *Service) handleBenchGet(w http.ResponseWriter, r *http.Request) {
	raw, err := s.Bench.Get(chi.URLParam(r, "id"))
	if err != nil {
		writeBenchLookupError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(raw)
}

func (s *Service) handleBenchDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Bench.Delete(chi.URLParam(r, "id")); err != nil {
		writeBenchLookupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeBenchLookupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidID):
		writeError(w, http.StatusBadRequest, "invalid id")
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "bench result not found")
	default:
		writeError(w, http.StatusInternalServerError, "bench store error")
	}
}
