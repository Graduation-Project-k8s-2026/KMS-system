# ---- 1단계: builder ----
FROM golang:1.23-alpine AS builder

WORKDIR /src

# go.mod/go.sum만 먼저 복사해 `go mod download`를 별도 레이어로 분리한다.
# Docker는 레이어 단위로 캐시하므로, 소스 코드만 바뀌고 의존성 목록
# (go.mod/go.sum)이 그대로면 이 레이어는 캐시에서 그대로 재사용된다 — 매번
# 전체 의존성을 다시 내려받지 않아도 되어 빌드가 훨씬 빨라진다.
COPY go.mod go.sum ./
RUN go mod download

# 의존성 레이어가 캐시된 뒤에야 전체 소스를 복사한다 — 이 순서를 지켜야
# "소스만 바뀐 경우"에 위 go mod download 레이어를 계속 재사용할 수 있다.
COPY . .

# CGO_ENABLED=0: cgo(C 컴파일러/libc 링크) 없이 순수 Go 표준 라이브러리만으로
# 빌드한다. internal/seal/benchmark.go가 참조하는 TPM 소프트웨어 시뮬레이터는
# cgo가 없으면 "using the simulator requires building with CGO"라는 에러를
# 런타임에 우아하게 반환할 뿐, 빌드 자체를 막지는 않는다 — 그래서
# CGO_ENABLED=0으로도 정상적으로 빌드된다.
# GOOS=linux: 베이스 이미지가 리눅스이므로 실행 환경에 맞춰 명시한다.
# 이 둘의 조합이 "외부 동적 라이브러리(glibc 등)에 의존하지 않는 정적
# 바이너리"를 만드는 핵심이다 — 그 덕분에 실행 스테이지가 musl libc를 쓰는
# alpine이어도(glibc가 아니어도) 문제없이 그대로 돌아간다.
# -ldflags="-s -w": 디버그 심볼(-w)과 심볼 테이블(-s)을 제거해 바이너리
# 크기를 줄인다 — 운영 환경에서 디버거로 붙일 일이 없다면 불필요한 정보다.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/server

# ---- 2단계: 실행 ----
FROM alpine:latest

# K8sSeal(KMS_SEAL_TYPE=k8s)이 K8s API 서버와 HTTPS로 통신할 때 TLS 인증서
# 체인을 검증하는 데 필요하다. 이게 없으면 그 경로에서만 원인이 알기 어려운
# TLS 에러가 날 수 있다 — 다른 seal 방식은 쓰지 않지만, 항상 갖춰두는 게
# 안전하고 이미지 크기 증가도 미미하다(수백 KB 수준).
RUN apk add --no-cache ca-certificates

# non-root 사용자로 실행하는 이유: 컨테이너 프로세스가 root로 돌다가
# 컨테이너 탈출(container escape) 취약점이나 잘못된 볼륨 마운트 등으로
# 뚫리면, 그 즉시 호스트 쪽에서도 root 권한에 가까운 피해로 이어질 위험이
# 커진다. 전용 non-root 사용자로 실행하면 그 프로세스가 건드릴 수 있는
# 파일/권한이 애초에 그 사용자 수준으로 제한되어 피해 범위가 줄어든다 —
# 컨테이너 이미지를 만들 때의 기본적인 보안 관례다.
RUN addgroup -S kms && adduser -S kms -G kms

# KMS_STORAGE=file일 때 파일 저장소가 쓰는 자리. 기본 KMS_DATA_DIR은
# "./data"이고 이 이미지의 기본 작업 디렉토리는 "/"이므로, 실제로는 이
# "/data" 디렉토리를 그대로 가리킨다. non-root 사용자가 쓰고 읽을 수 있도록
# 소유권을 미리 넘겨둔다.
RUN mkdir -p /data && chown -R kms:kms /data

# builder 스테이지에서 만든 정적 바이너리만 가져온다 — Go 툴체인, 소스
# 코드, 캐시된 모듈 등 빌드에만 필요했던 건 전부 이 최종 이미지에 남지
# 않는다.
COPY --from=builder /server /server

USER kms

EXPOSE 8200

ENTRYPOINT ["/server"]
