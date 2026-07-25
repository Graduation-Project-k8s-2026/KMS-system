package seal

// SealProfile은 각 Seal 구현체의 설계상 특성을 구조화된 값으로 나타낸다 —
// [결정 3] 비교 실험(Dev/Shamir/TPM/K8s)의 결과를 API/대시보드로 보여주기
// 위한 목적이다. 벤치마크(시간 측정, benchmark.go)와 달리 이 값들은 실행할
// 때마다 달라지는 게 아니라 설계 시점에 이미 정해진 "고정된 사실"이라,
// 매번 다시 계산하지 않고 순수 값을 반환하는 메서드로 각 Seal에 붙여둔다.
type SealProfile struct {
	Type string

	// RequiresHumans: Unseal에 사람의 개입(조각 제출 등)이 필수인가.
	RequiresHumans bool
	// HumanCount: 필요한 사람 수. Shamir는 threshold, 나머지는 0.
	HumanCount int

	// SinglePointOfFailure: 이 하나만 무너지면(또는 손에 넣으면) Root Key
	// 전체가 뚫리거나 영구히 사라지는 지점이 있는가.
	SinglePointOfFailure bool
	// HardwareDependent: 특정 물리 장치(TPM 칩 등)에 묶여 있는가.
	HardwareDependent bool
	// AutoUnsealCapable: 사람 개입 없이 자동으로 Unseal할 수 있는가.
	AutoUnsealCapable bool

	// Notes: 이 방식만의 특이사항을 한 줄로.
	Notes string
}

// Profiler는 Profile() SealProfile을 제공하는 Seal 구현체를 나타낸다.
//
// 이 메서드를 Seal 인터페이스(seal.go) 자체에 넣지 않은 이유: Profile은
// "이 seal이 어떤 성격을 가졌는지"에 대한 부가 정보일 뿐, barrier가 실제
// Unseal 흐름을 돌리는 데 필요한 핵심 계약(Unseal/Type/IsConfigured)이
// 아니다. 필요한 곳(API 핸들러, 벤치마크)에서만 이 작은 별도 인터페이스로
// 타입 단언하면 충분하고, Seal 인터페이스 자체는 계속 최소한으로 유지된다.
type Profiler interface {
	Profile() SealProfile
}

// Profile은 DevSeal의 특성을 반환한다.
func (s *DevSeal) Profile() SealProfile {
	return devProfile()
}

func devProfile() SealProfile {
	return SealProfile{
		Type:                 "dev",
		RequiresHumans:       false,
		HumanCount:           0,
		SinglePointOfFailure: true,
		HardwareDependent:    false,
		AutoUnsealCapable:    true,
		Notes:                "개발용, 단일 패스프레이즈가 유일한 방어선",
	}
}

// Profile은 ShamirSeal의 특성을 반환한다. HumanCount는 이 인스턴스가 실제로
// 요구하는 threshold 값을 그대로 반영한다.
func (s *ShamirSeal) Profile() SealProfile {
	return shamirProfile(s.threshold)
}

func shamirProfile(threshold int) SealProfile {
	return SealProfile{
		Type:                 "shamir",
		RequiresHumans:       true,
		HumanCount:           threshold,
		SinglePointOfFailure: false,
		HardwareDependent:    false,
		AutoUnsealCapable:    false,
		Notes:                "자동 unseal 불가 — 조각을 사람이 여러 번 제출해야 함",
	}
}

// Profile은 TPMSeal의 특성을 반환한다.
func (s *TPMSeal) Profile() SealProfile {
	return tpmProfile()
}

func tpmProfile() SealProfile {
	return SealProfile{
		Type:                 "tpm",
		RequiresHumans:       false,
		HumanCount:           0,
		SinglePointOfFailure: true,
		HardwareDependent:    true,
		AutoUnsealCapable:    true,
		Notes:                "하드웨어 고장 시 Root Key 영구 소실",
	}
}

// Profile은 K8sSeal의 특성을 반환한다.
func (s *K8sSeal) Profile() SealProfile {
	return k8sProfile()
}

func k8sProfile() SealProfile {
	return SealProfile{
		Type:                 "k8s",
		RequiresHumans:       false,
		HumanCount:           0,
		SinglePointOfFailure: false,
		HardwareDependent:    false,
		AutoUnsealCapable:    true,
		Notes: "위임 구조라 '단일 장애점'의 의미가 다르다 — 우리 코드 안에는 SPOF가 " +
			"없지만, 실제 보안은 K8s Secret이 base64 인코딩일 뿐이라는 점 때문에 " +
			"클러스터 설정(특히 etcd encryption at rest 여부)에 전적으로 의존한다",
	}
}
