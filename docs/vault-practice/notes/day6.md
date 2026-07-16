# Day 6 - 클라우드 3사(AWS/Azure/GCP) vs Hashi Vault 비교

비교 방식: 개념 하나를 고정하고 4개(Vault 포함)를 나란히 비교 (한 클라우드씩 보지 않음)
전제: Vault는 지금까지 실습한 참고 구현일 뿐, 우리 정답이 아님. "업계는 이 문제를 어떻게 풀었나"를 보는 것.

================================================================
## 1. 루트 키 보호 방식 (Day 5와 직결)
================================================================

핵심 대응: Vault의 "Shamir 조각들"이 하던 '신뢰의 뿌리' 역할을, 클라우드는 'HSM 하드웨어'가 대신함.

| | AWS KMS | Azure Key Vault | GCP Cloud KMS |
|---|---|---|---|
| 보호 등급 | FIPS 140-3 Level 3 HSM(기본) | Standard: 140-2 L2 (다중테넌트) / Managed HSM: 140-3 L3 (단일테넌트) | Software: 140-3 L1 / Cloud HSM: 140-2 L3 |
| 평문 키 반출 | 절대 안 됨(HSM 경계 밖으로 안 나감, 디스크 기록 안 됨) | 절대 안 됨(추출 불가, MS에게도 평문 노출 안 됨) | 절대 안 됨(API로 내보내기/조회 불가, Google 직원도 접근 불가) |
| 사람이 unseal? | X (완전 자동) | X (단, Managed HSM의 Security Domain은 예외) | X (완전 자동) |

- 공통: "평문 키는 절대 밖으로 안 나간다" 원칙은 Vault와 동일.
- 큰 차이: 클라우드는 seal/unseal 개념을 고객에게 노출하지 않음. HSM이 물리적으로 항상 켜져있고 사업자가 가용성 책임.

### ★ 발견: Azure Managed HSM의 Security Domain = Vault의 Shamir와 거의 동일
- Managed HSM은 클러스터 복구를 승인하는 3~10개의 고객 관리형 키 집합(Security Domain)을 사용
- Microsoft도 이 키들 없이는 클러스터를 관리적으로 초기화 못 함
- Vault Shamir(재시작마다 필요) vs Azure(평상시엔 안 쓰고, 클러스터 재생성/재해복구 때만 사용)
  -> 같은 수학적 아이디어(정족수 분산)를 '일상 운영' 아닌 '비상 복구'에 적용

================================================================
## 2. 키 계층 / 봉투 암호화 표현 방식 (Day 2, 3과 직결)
================================================================

우리가 Day 2~3에서 "KEK/DEK"로 배운 건 사실 Azure/GCP의 공식 업계 용어. AWS만 다른 이름 사용.

### 계층 개수가 서로 다름 (★ 정정된 표)

| 계층 | Hashi Vault | AWS | Azure | GCP |
|---|---|---|---|---|
| 4단계(최상위) | Unseal keys(Shamir) | - | - | Root KMS Master Key (비공개, 문서에만 언급) |
| 3단계 | Root key | Root key = "KMS 키" (곧 KEK 역할) | KEK (HSM이 직접 보호, 위에 별도 마스터키 언급 없음) | KEK (공식 용어) |
| 2단계 | Keyring(my-key, 버전관리) | Data key(GenerateDataKey) | DEK (공식 용어) | DEK (공식 용어) |
| 1단계(최하위) | 저장 데이터 | S3/RDS 등 | Storage/SQL 등 | Storage/BigQuery 등 |

- AWS, Vault: 3단계 구조. AWS는 "루트키"와 "KEK"를 같은 것으로 취급(분리해서 안 부름).
- Azure: 문서상 KEK/DEK 2단계만 명시. 그 위 별도 마스터키 계층은 공개 안 함(HSM이 물리 보호막이라 소프트웨어 계층이 불필요하다고 보는 듯).
- GCP만 유일하게 4단계를 문서에서 명시적으로 인정("KMS Master Key가 KEK를 암호화").
- ★ 진짜 차이: "루트키가 절대 안 나간다"는 결과는 같지만, 그 루트키가 몇 겹인지를 얼마나 투명하게 공개하느냐가 다름. GCP가 제일 솔직, AWS/Azure는 블랙박스.

### Azure의 특이 활용: KEK 비활성화 = 암호학적 삭제(crypto shredding)
- KEK가 DEK 복호화에 필요 -> KEK만 비활성화하면 데이터를 물리적으로 안 지워도 "사실상 삭제" 효과

================================================================
## 3. 키 회전(rotation) 정책 (Day 3과 직결)
================================================================

"회전 = 새 버전 생성, 옛 버전 유지" 원리는 4개 모두 동일. 자동화/세밀 제어에서 차이.

### rotate의 정확한 정의 (못박기)
기존 키/데이터를 건드리지 않고, 같은 이름·역할을 유지하는 키에 새 버전(새 키 자료)을 추가하는 행위.
- 정체성(이름/역할/권한)은 유지 / 내용물(암호화 비트)만 새 버전으로 / 옛 버전은 삭제 안 됨(잔존)
- rewrap(옛 데이터를 새 버전으로 재암호화)은 회전의 결과를 데이터에 적용하는 별개 작업
- destroy(옛 버전 완전 삭제)도 회전이 아님

| | Vault | AWS | Azure | GCP |
|---|---|---|---|---|
| 최소 회전 주기 | 없음(자유) | 90일 | 28일 | 없음(자유) |
| 자동 회전 기본값 | 꺼짐(auto_rotate_period=0) | 꺼짐(명시 활성화) | 꺼짐(명시 활성화) | 꺼짐 |
| 온디맨드(수동) 회전 | rotate, 무제한 | API, 평생 10회 제한 | CLI, 무제한 | 버전 생성, 무제한 |
| 비대칭키 자동회전 | 지원 | X 불가 | 사실상 지원(RSA/EC 중심) | X 불가 |
| 옛 데이터 처리 | rewrap 수동 마이그레이션 | 자동 재암호화 없음(옛 버전 유지) | 버전 미지정 참조 시 최신 자동 사용 | 재암호화는 별도 과금 작업 |

- ★ AWS만 온디맨드 회전에 '평생 10회' 상한 -> 과도한 버전 누적 방지 설계로 추정
- 설계 질문: 우리 KMS도 무제한 회전 허용? 아니면 제한? (Vault는 무제한이었음)

================================================================
## 4. 접근 제어 모델 (Day 4와 직결)
================================================================

Day 4에서 app-policy/admin-policy를 직접 설계한 것과 가장 밀접.

| | Vault | AWS | Azure | GCP |
|---|---|---|---|---|
| 기본 원칙 | deny-by-default | 명시 허용+절대 거부 안 됨 | RBAC: 역할 할당 기반 | IAM 역할 기반 |
| 정책 붙는 대상 | path(경로) | 키 자체(키정책)+IAM 둘 다 | 리소스(vault/key) 스코프 | 프로젝트/키링/키 스코프 |
| 관리 vs 사용 분리 | 정책 직접 설계(app/admin) | 키 정책 안 Sid로 구분 | Crypto Officer vs Crypto User(내장 역할) | cloudkms.admin vs cryptoKeyEncrypterDecrypter(내장 역할) |
| 특이 구조 | 단일 정책 체계 | ★이중 인가(키정책+IAM 둘 다 통과) | 레거시(Access Policy)->신규(RBAC) 전환 중 | IAM 단일, 세분화된 사전 역할 많음 |

### 용어 정리: IAM 정책이란?
- IAM = Identity and Access Management. IAM 정책 = '신원(사용자/역할/그룹)'에 붙는 권한 문서 ("이 사람이 뭘 할 수 있나")
- 대비: 리소스 정책 = 리소스 자체(키 등)에 붙음 ("이 리소스에 누가 접근 가능한가"). AWS "키 정책"이 이 예시.
- 구조: Effect(Allow/Deny) + Action(kms:Encrypt 등) + Resource + Condition(선택)
- Vault Policy와 개념적으로 거의 1:1 대응:
  Vault path ≈ IAM Resource / Vault capabilities ≈ IAM Action / 토큰에 정책 부착 ≈ IAM 정책을 신원에 attach

### AWS 이중 인가(dual authorization)
- 대부분 AWS 리소스는 IAM 정책만으로 접근 결정. 그런데 KMS는 '키 정책'과 'IAM 정책'이 둘 다 허용해야 함.
- 키 정책이 막고 있으면 IAM에서 아무리 허용해도 소용 없음(키 정책이 먼저 문을 열어줘야 함).
- Grant라는 제3 메커니즘: 권한 위임을 다시 위임(자식 grant 생성)까지 가능.
- 의미: "키 소유자"와 "IAM 관리자"가 다른 사람일 수 있는 대규모 조직에서 특히 유효한 안전장치.

### ★ 핵심 통찰
Day 4에서 우리는 정책을 '직접 작성'했지만(Vault 방식),
Azure/GCP는 '사전 정의된 역할 중 선택'(Crypto User/Officer, cloudkms.admin 등).
-> 설계 선택: 사용자가 정책을 자유 작성(유연/실수위험↑) vs 사전 역할 선택(안전/유연성↓)

================================================================
## Day 6 종합 통찰
================================================================
- 4개 서비스 모두 근본 원리는 동일(봉투 암호화 반복, deny-by-default, 평문키 반출금지, 회전=버전추가).
- 진짜 차이는 '신뢰의 뿌리'를 어디에 두느냐:
  - Vault = 사람들(Shamir 조각) = 소프트웨어로 신뢰 분산
  - 클라우드 = 인증된 HSM 하드웨어 = 신뢰를 하드웨어에 위임
- 이것이 Day 1의 설계 질문 "HSM을 흉내낼 것인가, 소프트웨어로만 구현할 것인가"에 대한 업계의 두 가지 답.

================================================================
## 참고 원본 문서 (Day 6 전체, 중복 제거)
================================================================

[표준]
- NIST SP 800-57 Part 1 Rev.5: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- NIST FIPS 140-3: https://csrc.nist.gov/pubs/fips/140-3/final

[AWS]
- 데이터 보호(HSM 경계): https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html
- Features: https://aws.amazon.com/kms/features/
- Cryptography essentials(봉투암호화): https://docs.aws.amazon.com/kms/latest/developerguide/kms-cryptography.html
- Overview(루트키 계층): https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
- FAQs(회전 90일~7년, 온디맨드 10회): https://aws.amazon.com/kms/faqs/
- 키 정책: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- IAM 정책: https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies.html
- 접근 제어 개요(이중 인가): https://docs.aws.amazon.com/kms/latest/developerguide/control-access.html

[Azure]
- Managed HSM 개요: https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview
- Security Domain(데이터 통제): https://github.com/MicrosoftDocs/azure-security-docs/blob/main/articles/key-vault/managed-hsm/mhsm-control-data.md
- 저장 데이터 암호화(KEK/DEK 공식 용어): https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest
- 키 회전 정책 설정: https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation
- RBAC vs Access Policy: https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-access-policy
- Key Vault용 내장 역할(Crypto User/Officer): https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security

[GCP]
- 보호 수준(Software/HSM): https://docs.cloud.google.com/kms/docs/protection-levels
- 키 관리 Deep Dive(Root KMS Master Key, KEK/DEK): https://docs.cloud.google.com/docs/security/key-management-deep-dive
- Cloud HSM 아키텍처: https://docs.cloud.google.com/docs/security/cloud-hsm-architecture
- 봉투 암호화: https://docs.cloud.google.com/kms/docs/envelope-encryption
- 키 회전: https://docs.cloud.google.com/kms/docs/key-rotation
EOF