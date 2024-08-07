package task

type TaskJson struct {
	Name            string `json:"name"`
	Language        string `json:"language"`
	Path            string `json:"path"`
	ApplicationPath string `json:"applicationPath"`
}