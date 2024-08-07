package utils

import (
	"os"
)

func Getenv(env, defaultVal string) string {
	envVal := os.Getenv(env)
	if IsEmpty(envVal) {
		envVal = defaultVal
	}
	return envVal
}
