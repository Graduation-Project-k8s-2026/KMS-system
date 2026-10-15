# Campus Store 배포

현재 사용자 경로는 **공개 HTTPS → 스토어 → 내부 KMS**입니다. Tailscale 설치·가입이 필요 없습니다. KMS 관리 화면은 기존 사설 경로에 유지합니다.

```bash
# 공개 데모 HTTPS 준비 + 앱 배포
python3 deploy/campus-store/publish.py
# 현재 주소와 접속 암호 파일 위치 확인 (암호는 출력하지 않음)
python3 deploy/campus-store/publish.py --status
# 운영 접근 없는 구성 검토
python3 deploy/campus-store/deploy.py --plan --runtime /tmp/campus-store-plan
```

공통 접속 계정은 `demo`입니다. 암호는 `~/kms-lab/campus-store/access-password`에만 보관합니다. Quick Tunnel은 임시 주소이며 재시작 시 주소가 바뀔 수 있습니다. Portal은 갱신된 origin 파일을 읽습니다. 고정 서비스가 필요하면 별도 도메인과 고정 터널 또는 HTTPS 프록시로 전환합니다.

`resources.example.json`은 자리표시자가 있는 검토용 파일이므로 직접 적용하지 않습니다. 현재 `deploy.py` 기본값은 `--access public`이며, `--access private`는 과거 Tailscale 경로를 명시적으로 선택하는 옵션입니다.

실제 공개 경로 검증:

```bash
python3 deploy/campus-store/verify_live.py --restart-portal --output docs/demo/evidence/campus-store-public-live.json
python3 deploy/campus-store/verify_public_ui.py
```

가상 주문 생성과 Portal 재시작을 수반합니다. KMS 키 정책은 바꾸지 않습니다. 브라우저 검증은 개발 환경의 Playwright·Chromium을 사용합니다.

[구성도·실행 절차](../../docs/demo/campus-store.md) · [검증 결과](../../docs/demo/verification.md)
