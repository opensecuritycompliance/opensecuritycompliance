package vo

type SecurityContext struct {
	InternalPrivilege []string
	AuthToken         string
	ID                string
}
