package vo

type ErrorCode int

const (
	ServiceDown ErrorCode = 1<<iota + 1
	BadInputJSONFormat
)

type ErrorVO struct {
	Criticality  string           `json:",omitempty"`
	Message      string           `json:",omitempty"`
	Description  string           `json:",omitempty"`
	ErrorDetails []*ErrorDetailVO `json:",omitempty"`
	DebugID      string           `json:",omitempty"`
}

type ErrorDetailVO struct {
	Field    string
	Value    interface{}
	Location string
	Issue    string
}

type ErrorResponseVO struct {
	Error      *ErrorVO
	StatusCode int
}

type ErrorRespVO struct {
	ErrorMessage string
}
