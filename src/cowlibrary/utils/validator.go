package utils

import (
	"cowlibrary/vo"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/dmnlk/stringUtils"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

var Validate *validator.Validate

var NameAndVersionRegex = `^([a-zA-Z]+)(?::(\d+\.\d+\.\d+))?$`

func init() {
	Validate = validator.New()
	// Validate.RegisterValidation("name", NameValidation)
	Validate.RegisterValidation("name", func(fl validator.FieldLevel) bool {
		matched, err := regexp.MatchString(`^[A-Za-z0-9][A-Za-z0-9\s&,\-_>!?]*$`, fl.Field().String())
		if err != nil {
			return false
		}
		return matched
	})

	Validate.RegisterValidation("nameandversion", func(fl validator.FieldLevel) bool {
		matched, err := regexp.MatchString(NameAndVersionRegex, fl.Field().String())
		if err != nil {
			return false
		}
		return matched
	})

	Validate.RegisterValidation("rulename", func(fl validator.FieldLevel) bool {
		matched, err := regexp.MatchString(`^[A-Z][A-Za-z0-9]{0,49}$`, fl.Field().String())
		if err != nil {
			return false
		}
		return matched
	})

	Validate.RegisterValidation("taskname", func(fl validator.FieldLevel) bool {
		matched, err := regexp.MatchString(`^[A-Z][A-Za-z0-9]{0,49}$`, fl.Field().String())
		if err != nil {
			return false
		}
		return matched
	})
}

func NameValidation(fl validator.FieldLevel) bool {
	matched, err := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, fl.Field().String())
	if err != nil {
		return false
	}
	return matched
}

// GetErrorMsg : user defined error message for validation
func GetErrorMsg(fe validator.FieldError) string {
	errorMsg := fe.Error()
	switch fe.Tag() {
	case "required":
		errorMsg = "this field is required"
	case "lte":
		errorMsg = "should be less than"
	case "gte":
		errorMsg = "should be greater than"
	case "email":
		errorMsg = "not a valid email"
	case "unique":
		errorMsg = "contains duplicate values"
	case "alpha":
		errorMsg = "should contain only characters"
	case "max":
		errorMsg = "should not exceed the limit"
	case "min":
		errorMsg = "should exceed the minimal requirement"
	case "alphanum":
		errorMsg = "should contain only numbers and text"
	case "oneof":
		errorMsg = "allowed values"
	case "actiontags":
		errorMsg = "not a valid structure for action tags"
	case "name":
		errorMsg = "special characters not allowed"
	case "eq":
		errorMsg = "the values should be"
	case "nameandversion":
		errorMsg = "not a valid pattern for name and version"
	}

	if stringUtils.IsNotEmpty(fe.Param()) {
		errorMsg += " : " + fe.Param()
	}

	return errorMsg
}

func GetValidationError(err error) []*vo.ErrorDetailVO {
	var ve validator.ValidationErrors
	errorDetails := make([]*vo.ErrorDetailVO, 0)
	if err != nil {
		if errors.As(err, &ve) {
			errorDetails = make([]*vo.ErrorDetailVO, len(ve))
			for i, fe := range ve {
				errorDetails[i] = &vo.ErrorDetailVO{Field: fe.Field(), Value: fe.Value(), Issue: GetErrorMsg(fe), Location: fe.StructNamespace()}
			}
		} else {
			errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: err.Error()})
		}
	}
	return errorDetails
}

func GetNameAndVersion(val string) (string, string) {
	regex := regexp.MustCompile(NameAndVersionRegex)
	match := regex.FindStringSubmatch(val)

	name, version := ``, ``

	if len(match) > 0 {
		name = match[0]
	}

	if len(match) > 1 {
		version = match[1]
	}

	return name, version
}

func ValidateIOMap(ioMap []string) error {

	inputs := make(map[string]interface{}, 0)

	targetOutputVariables := make([]string, 0)
	srcInputVariables := make([]string, 0)

	selfAssignVars := make([]string, 0)
	incorrectFormatErrors := make([]string, 0)
	sourceRefFormatErrors := make([]string, 0)
	targetRefFormatErrors := make([]string, 0)
	inValidFieldTypes := make([]string, 0)

	for _, iomap := range ioMap {
		iomapArr := strings.Split(iomap, ":=")

		if len(iomapArr) < 2 {
			incorrectFormatErrors = append(incorrectFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}
		targetArr := strings.Split(iomapArr[0], ".")
		if len(targetArr) < 3 {
			targetRefFormatErrors = append(targetRefFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}
		sourceArr := strings.Split(iomapArr[1], ".")
		if len(sourceArr) < 3 {
			sourceRefFormatErrors = append(sourceRefFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}

		if sourceArr[0] == "*" && sourceArr[1] == "Input" {
			inputs[sourceArr[2]] = nil
		}

		if sourceArr[0] == targetArr[0] && sourceArr[1] == targetArr[1] && sourceArr[2] == targetArr[2] {
			selfAssignVars = append(selfAssignVars, fmt.Sprintf("'%s'", targetArr[2]))
			continue
		}

		if targetArr[1] == "Input" && targetArr[0] == "*" {
			targetOutputVariables = append(targetOutputVariables, fmt.Sprintf("'%s'", targetArr[2]))
			continue
		}

		if sourceArr[1] == "Output" && sourceArr[0] == "*" {
			srcInputVariables = append(srcInputVariables, fmt.Sprintf("'%s'", sourceArr[2]))
			continue
		}

		fieldTypes := []string{"Input", "Output"}

		if !SliceContains(fieldTypes, sourceArr[1]) || !SliceContains(fieldTypes, targetArr[1]) {
			inValidFieldTypes = append(inValidFieldTypes, iomap)
		}

	}

	errorMsgs := make([]string, 0)

	if len(targetOutputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Assigning the output variable {%s} as input to the flow is not allowed.", strings.Join(targetOutputVariables, ",")))
	}

	if len(srcInputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("You cannot use the output variable of the rule as an input. {%s}", strings.Join(srcInputVariables, ",")))
	}

	if len(selfAssignVars) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Cannot assign a variable to itself. {%s}", strings.Join(selfAssignVars, ",")))
	}

	if len(incorrectFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("The provided mappings are incorrect. {%s}", strings.Join(incorrectFormatErrors, ",")))
	}

	if len(sourceRefFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid source format. {%s}", strings.Join(sourceRefFormatErrors, ",")))
	}

	if len(targetRefFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid target format. {%s}", strings.Join(targetRefFormatErrors, ",")))
	}

	if len(inValidFieldTypes) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid field types. {%s}", strings.Join(inValidFieldTypes, ",")))
	}

	if len(errorMsgs) > 0 {

		if len(errorMsgs) == 1 {
			return errors.New(errorMsgs[0])
		}

		orderedErrorMsgs := make([]string, 0)

		for i, errorMsg := range errorMsgs {
			orderedErrorMsgs = append(orderedErrorMsgs, fmt.Sprintf("%d. %s", i+1, errorMsg))
		}

		return errors.New(strings.Join(orderedErrorMsgs, "\n"))
	}

	return nil

}

func ValidateRule(ruleYAML *vo.RuleYAMLVO, additionalInfo *vo.AdditionalInfo) *vo.ErrorVO {
	_, err := GetTaskInfosFromRule(ruleYAML, additionalInfo)
	return err
}

func HandleValidationError(err error) []*vo.ErrorDetailVO {
	var ve validator.ValidationErrors
	errorDetails := make([]*vo.ErrorDetailVO, 0)
	if errors.As(err, &ve) {
		errorDetails = make([]*vo.ErrorDetailVO, len(ve))
		for i, fe := range ve {
			errorDetails[i] = &vo.ErrorDetailVO{Field: fe.Field(), Value: fe.Value(), Issue: GetErrorMsg(fe), Location: fe.StructNamespace()}
		}
	} else {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: err.Error()})
	}
	return errorDetails
}

func RegisterPCDefinedValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("actiontags", func(fl validator.FieldLevel) bool {
			return len(strings.Split(fl.Field().String(), ":")) == 2
		})

		v.RegisterValidation("name", func(fl validator.FieldLevel) bool {
			matched, err := regexp.MatchString(`^[A-Za-z0-9][A-Za-z0-9\s&,\-_>!?]*$`, fl.Field().String())
			if err != nil {
				return false
			}
			return matched
		})

		v.RegisterValidation("rulename", func(fl validator.FieldLevel) bool {
			matched, err := regexp.MatchString(`^[A-Z][A-Za-z0-9]{0,49}$`, fl.Field().String())
			if err != nil {
				return false
			}
			return matched
		})

		v.RegisterValidation("datacatalogcategory", func(fl validator.FieldLevel) bool {
			matched, err := regexp.MatchString(`^[a-zA-Z0-9/ ]+$`, fl.Field().String())
			if err != nil {
				return false
			}
			return matched
		})

		v.RegisterValidation("taskname", func(fl validator.FieldLevel) bool {
			matched, err := regexp.MatchString(`^[A-Z][A-Za-z0-9]{0,49}$`, fl.Field().String())
			if err != nil {
				return false
			}
			return matched
		})
	}
}
