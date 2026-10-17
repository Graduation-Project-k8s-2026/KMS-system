// Package tlsreload: TLS 인증서 파일이 바뀌면 서버를 재시작하지 않고 새 인증서를 쓰게 한다.
//
// 동작: tls.Config.GetCertificate는 핸드셰이크마다 불린다. 매번 파일을 읽으면 느리므로 인증서를 메모리에
// 캐시하고, 마지막 확인 후 Interval(기본 30초) 이상 지났을 때만 파일의 mtime·크기를 본다. 바뀐 경우에만 다시
// 읽는다. 새 파일을 읽다 실패하면(반쯤 쓴 파일, 인증서와 키 불일치 등) 이전 인증서를 계속 쓰고 로그를 남긴다 —
// 갱신 작업의 실수가 서비스 중단으로 번지지 않게 하려는 것이다. 호출자는 새 파일을 임시 이름으로 쓴 뒤 mv로
// 바꾸는 것(원자적 교체)을 권장한다.
package tlsreload

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// DefaultInterval: 파일 변경 확인 최소 간격.
const DefaultInterval = 30 * time.Second

type stamp struct {
	mtime time.Time
	size  int64
}

type Reloader struct {
	certFile, keyFile string
	Interval          time.Duration
	now               func() time.Time // 테스트에서 주입

	mu        sync.Mutex
	cert      *tls.Certificate
	loaded    [2]stamp // 마지막으로 성공적으로 읽은 시점의 (cert, key) 파일 상태
	lastCheck time.Time
}

// New는 인증서를 한 번 읽는다. 처음 읽기에 실패하면 에러(서버 기동 실패)다.
func New(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile, Interval: DefaultInterval, now: time.Now}
	if err := r.load(); err != nil {
		return nil, err
	}
	r.lastCheck = r.now()
	return r, nil
}

func statOf(path string) (stamp, error) {
	st, err := os.Stat(path)
	if err != nil {
		return stamp{}, err
	}
	return stamp{st.ModTime(), st.Size()}, nil
}

// load는 파일을 읽어 성공했을 때만 캐시를 교체한다.
func (r *Reloader) load() error {
	cs, err := statOf(r.certFile)
	if err != nil {
		return err
	}
	ks, err := statOf(r.keyFile)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.loaded = &pair, [2]stamp{cs, ks}
	return nil
}

// GetCertificate는 tls.Config.GetCertificate에 그대로 넣는다.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); now.Sub(r.lastCheck) >= r.Interval {
		r.lastCheck = now
		cs, cerr := statOf(r.certFile)
		ks, kerr := statOf(r.keyFile)
		switch {
		case cerr != nil || kerr != nil:
			log.Printf("tlsreload: cannot stat certificate files, keeping the previous certificate: %v %v", cerr, kerr)
		case cs != r.loaded[0] || ks != r.loaded[1]:
			if err := r.load(); err != nil {
				log.Printf("tlsreload: new certificate could not be loaded, keeping the previous one: %v", err)
			} else {
				log.Print("tlsreload: certificate reloaded")
			}
		}
	}
	return r.cert, nil
}

// Config는 이 Reloader를 쓰는 서버용 tls.Config를 만든다.
func (r *Reloader) Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.GetCertificate}
}
