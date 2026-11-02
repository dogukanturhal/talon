# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Test suite for ztna_baseline.rego. Run via:
#
#   opa test docs/policy/ztna/ -v
#
# These tests pin the tier × sensitivity × AAL matrix in
# ztna_baseline.rego so accidental matrix-row drift surfaces in CI.

package talon.route

import rego.v1

# Synthetic fixtures keyed for readability.
fresh_posture_corp := {
	"iss": "https://posture.example.com",
	"subject": "device:tpm:abc123",
	"iat": time.now_ns() / 1000000000 - 60,  # 60s ago — fresh
	"compliance": {
		"tier": "TIER_CORP",
		"device_cert_valid": true,
		"network_class": "trusted",
		"route_sensitivity": "medium",
	},
}

fresh_posture_byod := {
	"iss": "https://posture.example.com",
	"subject": "device:apple-app-attest:xyz",
	"iat": time.now_ns() / 1000000000 - 60,
	"compliance": {
		"tier": "TIER_BYOD",
		"device_cert_valid": false,
		"network_class": "internet",
		"route_sensitivity": "low",
	},
}

stale_posture_corp := {
	"iss": "https://posture.example.com",
	"subject": "device:tpm:abc123",
	"iat": time.now_ns() / 1000000000 - 3600,  # 1h ago — stale for corp
	"compliance": {
		"tier": "TIER_CORP",
		"device_cert_valid": true,
		"network_class": "trusted",
		"route_sensitivity": "medium",
	},
}

user_aal3_hwk := {
	"sub": "01HZZ...",
	"email": "ops@example.com",
	"groups": ["platform_admin"],
	"roles": ["platform_admin"],
	"amr": ["pwd", "hwk"],
	"amr_recency_seconds": 1800,
}

user_aal2_otp := {
	"sub": "01HZZ...",
	"email": "user@example.com",
	"groups": ["users"],
	"roles": ["viewer"],
	"amr": ["pwd", "otp"],
	"amr_recency_seconds": 1800,
}

user_aal1_pwd := {
	"sub": "01HZZ...",
	"email": "user@example.com",
	"groups": ["users"],
	"roles": ["viewer"],
	"amr": ["pwd"],
	"amr_recency_seconds": 1800,
}

req := {
	"method": "GET",
	"path": "/api/v1/foo",
	"src_ip": "10.0.20.42",
}

route_medium := {
	"host": "grafana.internal.example.com",
	"permission": "viewer",
}

# ------------------------------------------------------------------ #

test_corp_aal3_medium_allows if {
	allow with input as {
		"user": user_aal3_hwk,
		"route": route_medium,
		"request": req,
		"posture": fresh_posture_corp,
	}
}

test_corp_aal2_medium_allows if {
	allow with input as {
		"user": user_aal2_otp,
		"route": route_medium,
		"request": req,
		"posture": fresh_posture_corp,
	}
}

test_corp_aal1_denies if {
	not allow with input as {
		"user": user_aal1_pwd,
		"route": route_medium,
		"request": req,
		"posture": fresh_posture_corp,
	}
}

test_no_posture_denies if {
	not allow with input as {
		"user": user_aal3_hwk,
		"route": route_medium,
		"request": req,
	}
}

test_stale_posture_denies if {
	not allow with input as {
		"user": user_aal3_hwk,
		"route": route_medium,
		"request": req,
		"posture": stale_posture_corp,
	}
}

test_byod_aal3_low_allows if {
	posture := {
		"iat": time.now_ns() / 1000000000 - 60,
		"compliance": {
			"tier": "TIER_BYOD",
			"device_cert_valid": false,
			"network_class": "internet",
			"route_sensitivity": "low",
		},
	}
	allow with input as {
		"user": user_aal3_hwk,
		"route": route_medium,
		"request": req,
		"posture": posture,
	}
}

test_byod_critical_route_denies if {
	posture := {
		"iat": time.now_ns() / 1000000000 - 60,
		"compliance": {
			"tier": "TIER_BYOD",
			"device_cert_valid": false,
			"network_class": "internet",
			"route_sensitivity": "critical",
		},
	}
	not allow with input as {
		"user": user_aal3_hwk,
		"route": route_medium,
		"request": req,
		"posture": posture,
	}
}

test_critical_route_requires_aal3 if {
	posture := {
		"iat": time.now_ns() / 1000000000 - 60,
		"compliance": {
			"tier": "TIER_CORP",
			"device_cert_valid": true,
			"network_class": "trusted",
			"route_sensitivity": "critical",
		},
	}
	not allow with input as {
		"user": user_aal2_otp,
		"route": route_medium,
		"request": req,
		"posture": posture,
	}
}

test_corp_critical_aal3_with_step_up_allows if {
	posture := {
		"iat": time.now_ns() / 1000000000 - 60,
		"compliance": {
			"tier": "TIER_CORP",
			"device_cert_valid": true,
			"network_class": "trusted",
			"route_sensitivity": "critical",
		},
	}
	stepped_up := object.union(user_aal3_hwk, {"amr_recency_seconds": 60})  # 1 min ago
	allow with input as {
		"user": stepped_up,
		"route": route_medium,
		"request": req,
		"posture": posture,
	}
}

test_breakglass_with_approval_allows if {
	posture := {
		"iat": time.now_ns() / 1000000000 - 60,
		"compliance": {
			"tier": "TIER_BREAKGLASS",
			"route_sensitivity": "critical",
		},
	}
	breakglass_user := {
		"sub": "01HZZ...",
		"amr": ["pwd", "hwk", "approval"],
		"amr_recency_seconds": 60,
	}
	allow with input as {
		"user": breakglass_user,
		"route": route_medium,
		"request": req,
		"posture": posture,
	}
}

test_breakglass_without_approval_denies if {
	posture := {
		"iat": time.now_ns() / 1000000000 - 60,
		"compliance": {
			"tier": "TIER_BREAKGLASS",
			"route_sensitivity": "critical",
		},
	}
	no_approval := user_aal3_hwk
	not allow with input as {
		"user": no_approval,
		"route": route_medium,
		"request": req,
		"posture": posture,
	}
}

# ------------------------------------------------------------------ #
# deny_reason tests — concrete strings matter for the audit log
# ------------------------------------------------------------------ #

test_no_posture_deny_reason if {
	r := deny_reason with input as {
		"user": user_aal3_hwk,
		"route": route_medium,
		"request": req,
	}
	contains(r, "missing posture")
}

test_stale_posture_deny_reason if {
	r := deny_reason with input as {
		"user": user_aal3_hwk,
		"route": route_medium,
		"request": req,
		"posture": stale_posture_corp,
	}
	contains(r, "posture stale")
}
