// Package storage: 저장 백엔드. StorageBackend 인터페이스와 구현체를 담는다.
package storage

// StorageBackend는 "이미 암호화된 바이트를 어딘가에 저장하고 다시 꺼내온다"는
// 동작만 추상화한 인터페이스다. 이 계층은 저장하는 내용이 무엇인지 전혀 모른다 —
// 평문이든 KEK든 무엇이든, 여기 도달하는 시점엔 이미 암호화가 끝나 있어야 한다는
// 원칙을 인터페이스 경계로 강제하는 것이 이 패키지의 핵심 목적이다.
//
// Seal 인터페이스와 마찬가지로, 이 인터페이스를 만족하는 구현체라면 무엇이든
// 갈아끼울 수 있다 — 지금은 메모리(MemoryStorage)와 파일(FileStorage)이지만,
// 나중에 etcd나 실제 DB로 바꾸고 싶으면 이 인터페이스를 만족하는 새 구현체 하나만
// 추가하면 된다. 이 인터페이스를 사용하는 상위 코드(keys 등)는 전혀 손댈 필요가 없다.
type StorageBackend interface {
	// Get은 key에 저장된 값을 반환한다.
	// key가 존재하지 않으면 (nil, nil)을 반환한다 — 에러가 아니라 "없음"이라는
	// 정상적인 상태로 취급한다. "이 키가 있는지 확인하고 싶을 뿐인데 매번 에러를
	// 구분해서 처리해야 하는" 번거로움을 없애기 위함이다 (예: 키 회전 로직에서
	// "이 버전이 아직 없으면 새로 만든다"를 표현할 때, err != nil 체크와
	// "없다"는 상태를 분리하지 않으면 진짜 I/O 에러와 혼동하기 쉽다).
	Get(key string) ([]byte, error)

	// Put은 key에 value를 저장한다. 이미 값이 있으면 덮어쓴다.
	Put(key string, value []byte) error

	// Delete는 key에 저장된 값을 삭제한다.
	Delete(key string) error

	// List는 prefix로 시작하는 모든 키에 대해, 그 키에서 prefix를 뗀 나머지
	// 부분만 모아 반환한다.
	// 예: List("keys/") 호출 시 저장된 키가 "keys/app-secret"이면 결과는
	// ["app-secret"]이다.
	List(prefix string) ([]string, error)
}
