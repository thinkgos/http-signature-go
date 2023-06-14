package httpsign

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_Validator_Date(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		validator  Validator
		time       time.Time
		timeFormat string
		wantErr    error
	}{
		{
			name:       "date not in range - upper bound",
			validator:  NewDateValidator(),
			time:       now.Add(maxTimeGap + time.Second),
			timeFormat: http.TimeFormat,
			wantErr:    ErrDateNotInRange,
		},
		{
			name:       "date not in range - lower bound",
			validator:  NewDateValidator(),
			time:       now.Add(-maxTimeGap - time.Second),
			timeFormat: http.TimeFormat,
			wantErr:    ErrDateNotInRange,
		},
		{
			name:       "date format: http.TimeFormat",
			validator:  NewDateValidator(),
			time:       now,
			timeFormat: http.TimeFormat,
			wantErr:    nil,
		},
		{
			name:       "date format: time.RFC850",
			validator:  NewDateValidator(),
			time:       now,
			timeFormat: time.RFC850,
			wantErr:    nil,
		},
		{
			name:       "date format: time.ANSIC",
			validator:  NewDateValidator(),
			time:       now,
			timeFormat: time.ANSIC,
			wantErr:    nil,
		},
		{
			name:       "not support date format",
			validator:  NewDateValidator(),
			time:       now,
			timeFormat: time.RFC3339,
			wantErr:    ErrDateInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			r.Header.Set(DateHeader, tt.time.UTC().Format(tt.timeFormat)) // should be UTC time
			err := tt.validator.Validate(r, &Parameter{})
			require.Equal(t, tt.wantErr, err)
		})
	}
}
