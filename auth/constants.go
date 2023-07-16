package auth

import (
	"strings"

	"github.com/google/uuid"
)

const ios_app_version = "1744"

var ios_device_id string

func init() {
	// Capitalize all letters
	ios_device_id = strings.ToUpper(uuid.New().String())
}
