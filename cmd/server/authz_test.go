package main

import (
	"errors"
	"testing"
)

// TestBuildAuthzAuthorizer_Off_ReturnsNil은 KMS_AUTHZ가 설정되지 않으면
// (기본값 off) 인가기 없이 nil을 반환하는지 확인한다 — Transit 라우터는
// nil Authorizer를 "인가 미들웨어 없음"으로 취급한다.
func TestBuildAuthzAuthorizer_Off_ReturnsNil(t *testing.T) {
	a, err := buildAuthzAuthorizer(true)
	if err != nil {
		t.Fatalf("buildAuthzAuthorizer(true) with KMS_AUTHZ unset failed: %v", err)
	}
	if a != nil {
		t.Fatalf("authorizer = %v, want nil (KMS_AUTHZ=off)", a)
	}
}

// TestBuildAuthzAuthorizer_OnWithoutAuthn_Fails는 KMS_AUTHZ=on인데
// authnEnabled=false(=KMS_AUTHN=off)면 기동을 실패시키는 에러를 반환하는지
// 확인한다 — 신원 없이는 권한을 판단할 근거가 없다.
func TestBuildAuthzAuthorizer_OnWithoutAuthn_Fails(t *testing.T) {
	t.Setenv("KMS_AUTHZ", "on")

	_, err := buildAuthzAuthorizer(false)
	if err == nil {
		t.Fatal("buildAuthzAuthorizer(false) with KMS_AUTHZ=on succeeded, want error")
	}
	if !errors.Is(err, errAuthzRequiresAuthn) {
		t.Fatalf("error = %v, want %v", err, errAuthzRequiresAuthn)
	}
}

// TestBuildAuthzAuthorizer_OnWithAuthn_NoClusterAccess_Fails는
// KMS_AUTHZ=on, authnEnabled=true인데 KMS_KUBECONFIG도 in-cluster 설정도
// 없는(테스트 환경이 곧 이 상태다) 경우 클라이언트 구성 실패로 에러를
// 반환하는지 확인한다 — "kubeconfig/in-cluster 둘 다 실패하면 기동을
// 실패시킨다" 요구사항의 반대편(authz 자체는 켜졌지만 K8s 접근이 안 되는
// 경우)을 검증한다.
func TestBuildAuthzAuthorizer_OnWithAuthn_NoClusterAccess_Fails(t *testing.T) {
	t.Setenv("KMS_AUTHZ", "on")
	t.Setenv("KMS_KUBECONFIG", "")

	if _, err := buildAuthzAuthorizer(true); err == nil {
		t.Fatal("buildAuthzAuthorizer(true) succeeded without KMS_KUBECONFIG or in-cluster config, want error")
	}
}
