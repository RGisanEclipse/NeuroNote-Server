package rate

import (
	"time"
)

type client struct {
    requests    int
    windowStart time.Time
}