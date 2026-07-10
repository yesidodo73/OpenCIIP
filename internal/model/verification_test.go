package model

import "testing"

func TestVerificationValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   Verification
		wantErr bool
	}{
		{name: "pending", value: Verification{State: VerificationPending}},
		{
			name: "rejected with environment",
			value: Verification{
				State:        VerificationRejected,
				Environments: []string{"Rocky Linux 9.8"},
			},
		},
		{
			name: "verified",
			value: Verification{
				State:        VerificationVerified,
				Environments: []string{"Rocky Linux 9.8 amd64"},
				VerifiedAt:   "2026-07-11T12:34:56Z",
			},
		},
		{name: "missing state", value: Verification{}, wantErr: true},
		{name: "unknown state", value: Verification{State: "approved"}, wantErr: true},
		{
			name: "leading whitespace",
			value: Verification{
				State:        VerificationPending,
				Environments: []string{" Rocky Linux 9.8"},
			},
			wantErr: true,
		},
		{
			name: "embedded newline",
			value: Verification{
				State:        VerificationPending,
				Environments: []string{"Rocky Linux\n9.8"},
			},
			wantErr: true,
		},
		{
			name: "embedded carriage return",
			value: Verification{
				State:        VerificationPending,
				Environments: []string{"Rocky Linux\r9.8"},
			},
			wantErr: true,
		},
		{
			name: "embedded nul",
			value: Verification{
				State:        VerificationPending,
				Environments: []string{"Rocky Linux\x009.8"},
			},
			wantErr: true,
		},
		{
			name: "duplicate environment",
			value: Verification{
				State:        VerificationPending,
				Environments: []string{"Rocky Linux 9.8", "Rocky Linux 9.8"},
			},
			wantErr: true,
		},
		{
			name: "verified without environment",
			value: Verification{
				State:      VerificationVerified,
				VerifiedAt: "2026-07-11T12:34:56Z",
			},
			wantErr: true,
		},
		{
			name: "verified with invalid time",
			value: Verification{
				State:        VerificationVerified,
				Environments: []string{"Rocky Linux 9.8"},
				VerifiedAt:   "2026-07-11",
			},
			wantErr: true,
		},
		{
			name: "pending with verified time",
			value: Verification{
				State:      VerificationPending,
				VerifiedAt: "2026-07-11T12:34:56Z",
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.value.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}
