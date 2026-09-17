// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"time"
)

func TestParseWindow(t *testing.T) {
	cases := []struct {
		in        string
		wantStart string
		wantEnd   string
		wantErr   bool
	}{
		{"2026-Q1", "2026-01-01", "2026-04-01", false},
		{"2026-Q2", "2026-04-01", "2026-07-01", false},
		{"2026-Q4", "2026-10-01", "2027-01-01", false},
		{"2026-06", "2026-06-01", "2026-07-01", false},
		{"2026-Q5", "", "", true},
		{"garbage", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			w, err := parseWindow(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if w.start.Format("2006-01-02") != tc.wantStart {
				t.Errorf("start=%s want=%s", w.start, tc.wantStart)
			}
			if w.end.Format("2006-01-02") != tc.wantEnd {
				t.Errorf("end=%s want=%s", w.end, tc.wantEnd)
			}
		})
	}
}

func TestNistTenet6_HappyPath(t *testing.T) {
	win := windowSpec{
		start: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		end:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	in := []auditRecord{
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), Decision: "allow", EvaluationMs: ptrInt64(4)},
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), Decision: "deny", EvaluationMs: ptrInt64(2)},
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), Decision: "allow", EvaluationMs: ptrInt64(0)},
		// no Decision — skipped by the query.
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)},
	}
	evd := nistControls()[0].compute(in, win)
	if evd.Measurement["evaluations_with_decision"].(int) != 3 {
		t.Errorf("withDec: got %v want 3", evd.Measurement["evaluations_with_decision"])
	}
	if evd.Measurement["evaluations_with_evaluation_ms_gt_0"].(int) != 2 {
		t.Errorf("withMs: got %v want 2", evd.Measurement["evaluations_with_evaluation_ms_gt_0"])
	}
	ratio := evd.Measurement["ratio"].(float64)
	if ratio < 0.666 || ratio > 0.667 {
		t.Errorf("ratio: got %v want ~0.667", ratio)
	}
	if evd.Satisfied {
		t.Error("expected NOT satisfied (ratio < 0.999)")
	}
}

func TestSOC2_CC63_AAL3Ratio(t *testing.T) {
	win := windowSpec{
		start: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		end:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	in := []auditRecord{
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), AMR: []string{"pwd", "hwk"}},
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), AMR: []string{"pwd", "hwk"}},
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), AMR: []string{"pwd", "otp"}},
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), AMR: []string{}},
	}
	// 3 with AMR (the empty array is skipped); 2 have hwk → ratio 0.666...
	evd := soc2Controls()[1].compute(in, win)
	if evd.Measurement["records_with_amr"].(int) != 3 {
		t.Errorf("got %v records_with_amr", evd.Measurement["records_with_amr"])
	}
	if evd.Measurement["records_with_hwk"].(int) != 2 {
		t.Errorf("got %v records_with_hwk", evd.Measurement["records_with_hwk"])
	}
	if evd.Satisfied {
		t.Error("expected NOT satisfied (0.667 < 0.95)")
	}
}

func TestBeyondCorpCBA_AllPass(t *testing.T) {
	win := windowSpec{
		start: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		end:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	tru := true
	in := []auditRecord{
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), DeviceCertValid: &tru},
		{Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), DeviceCertValid: &tru},
	}
	evd := beyondCorpControls()[0].compute(in, win)
	if !evd.Satisfied {
		t.Errorf("expected satisfied: %v", evd.Measurement)
	}
}

func ptrInt64(v int64) *int64 { return &v }
