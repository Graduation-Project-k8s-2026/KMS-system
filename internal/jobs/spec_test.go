package jobs

import "testing"

// 시간 기준 시험은 count를 요구하지 않는다: duration만 있으면 count는 상한으로 채워진다. 횟수 기준은 그대로 count가 필요하다.
func TestSpecNormalizeAllowsDurationWithoutCount(t *testing.T) {
	base := Spec{Mode: "transit", Scenario: "basic", Operation: "roundtrip", Concurrency: 4, Payload: 1024}

	s := base
	s.Duration = 60
	s.Normalize()
	if s.Count != 100000 || s.Validate() != nil {
		t.Fatalf("duration-only spec: count=%d err=%v", s.Count, s.Validate())
	}
	s = base
	s.Duration, s.Count = 60, 500 // 명시한 count는 그대로
	s.Normalize()
	if s.Count != 500 || s.Validate() != nil {
		t.Fatalf("explicit count changed: %d", s.Count)
	}
	for name, mod := range map[string]func(*Spec){
		"neither count nor duration": func(s *Spec) {},
		"negative count":             func(s *Spec) { s.Count = -1; s.Duration = 60 },
		"count too large":            func(s *Spec) { s.Count = 100001 },
		"duration too long":          func(s *Spec) { s.Duration = 301 },
	} {
		s := base
		mod(&s)
		s.Normalize()
		if s.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	s = base
	s.Count = 100
	if s.Normalize(); s.Count != 100 || s.Validate() != nil {
		t.Fatal("count-only spec broke")
	}
}
