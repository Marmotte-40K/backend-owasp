package models

import "time"

type User struct {
	ID                  int64
	Name                string
	Surname             string
	Password            string
	Email               string
	TotpSecret          string
	TotpEnabled         bool
	FailedLoginAttempts int
	LockedUntil         *time.Time
}
