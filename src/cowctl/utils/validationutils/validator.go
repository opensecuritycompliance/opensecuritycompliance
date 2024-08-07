package validationutils

import (
	cowlibutils "cowlibrary/utils"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/go-playground/validator/v10"
)

const MaxLen = 120

var ValidateString = func(input string) error {
	matched, err := regexp.MatchString(fmt.Sprintf(`^[A-Za-z][A-Za-z0-9\s&,.\-_>!?]{0,%d}$`, MaxLen), input)
	if err != nil || !matched {
		return errors.New("invalid  name")
	}
	return nil
}

var ValidateDate = func(input string) error {
	pattern := `^[0-9-]+$`
	re := regexp.MustCompile(pattern)
	if !re.MatchString(input) {
		return fmt.Errorf("invalid date format (expected YYYY-MM-DD)")
	}
	return nil
}

var ValidateVersion = func(input string) error {
	matched, err := regexp.MatchString(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`, input)
	if err != nil || (!matched && input != "latest") {
		return errors.New("invalid  version")
	}
	return nil
}

var ValidateName = func(input string) error {
	val := fmt.Sprintf(`^(?:[A-Za-z][A-Za-z0-9]{0,%d}|[A-Za-z]?)$`, MaxLen)
	matched, err := regexp.MatchString(val, input)
	if err != nil || !matched {
		return errors.New("invalid name")
	}
	return nil
}

var ValidateCCName = func(input string) error {
	val := fmt.Sprintf(`^(?:[A-Za-z][A-Za-z0-9\s]{0,%d}|[A-Za-z]?)$`, MaxLen)
	matched, err := regexp.MatchString(val, input)
	if err != nil || !matched {
		return errors.New("invalid name")
	}
	return nil
}

var ValidateAlpha = func(input string) error {
	var validate = validator.New()
	if err := validate.Var(input, fmt.Sprintf("required,alpha,gt=0,lt=%d", MaxLen)); err != nil {
		return errors.New("invalid name")
	}
	return nil
}

var ValidateAlphaName = func(input string) error {
	pattern := "^[A-Z][A-Za-z]*$"
	regex := regexp.MustCompile(pattern)
	if !regex.MatchString(input) {
		return errors.New("invalid name")
	}
	return nil

}

var ValidateFilePath = func(input string) error {
	if cowlibutils.IsEmpty(input) {
		return errors.New("invalid path")
	}
	_, err := os.Stat(input)
	if os.IsNotExist(err) {
		return err
	}
	return nil
}

var ValidateInt = func(input string) error {
	if cowlibutils.IsEmpty(input) {
		return errors.New("value cannot be empty")
	}

	_, err := strconv.Atoi(input)
	if err != nil {
		return errors.New("enter a valid number")
	}
	return nil
}

var ValidateVersionTyping = func(input string) error {
	matched, err := regexp.MatchString(`^[0-9.]+$`, input)
	if err != nil || !matched {
		return errors.New("invalid version")
	}
	return nil
}
