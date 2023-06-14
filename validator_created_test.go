package httpsign

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_Validator_Created(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name      string
		validator ValidatorTimestamp
		time      int64
		wantErr   error
	}{
		{
			name:      "created not in range - upper bound",
			validator: NewCreatedValidator(),
			time:      now + int64(maxTimeGap) + 1,
			wantErr:   ErrCreatedNotInRange,
		},
		{
			name:      "created not in range - lower bound",
			validator: NewCreatedValidator(),
			time:      now - int64(maxTimeGap) - 1,
			wantErr:   ErrCreatedNotInRange,
		},
		{
			name:      "created in range ",
			validator: NewCreatedValidator(),
			time:      now - 1,
			wantErr:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validator.ValidateTimestamp(tt.time)
			require.Equal(t, tt.wantErr, err)
		})
	}
}
