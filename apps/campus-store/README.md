# Campus Store

가상 캠퍼스 굿즈 쇼핑몰로 기존 KMS의 Transit 암호화, 서비스별 권한, 키 회전과 rewrap을 보여 주는 발표용 앱입니다.

현재 데모 접속은 공개 HTTPS이며 Tailscale 설치·가입이 필요 없습니다. `python3 deploy/campus-store/publish.py --status`로 주소를 확인하고, 계정 `demo`와 로컬 암호 파일로 입장합니다. KMS 관리 경로는 기존 사설 경로로 분리되어 있습니다.

- [시나리오·구성도·발표 순서·실행 방법](../../docs/demo/campus-store.md)
- [검증 결과와 운영 적용 상태](../../docs/demo/verification.md)
- [배포 도구](../../deploy/campus-store/deploy.py)

`server.py`는 `portal`, `checkout`, `shipping`, `marketing`, `migration` 모드로 실행합니다. 실행 환경에는 실제 KMS CA·JWT·내부 TLS 설정이 필요하며 암호화를 흉내 내는 실행 모드는 없습니다. 체험 계정은 실제 고객 인증이 아닙니다. 실제 개인정보 대신 제공된 가상 배송정보를 사용하세요.

```bash
python3 -m unittest discover -s apps/campus-store -p 'test_*.py' -v
```

Go fixture와 `verify_local.py`는 격리 검증용이며 앱 Docker 이미지에 포함되지 않습니다.
