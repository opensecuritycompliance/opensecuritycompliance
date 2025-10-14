package vo

// CriteriaVO :
type CriteriaVO struct {
	SortBy        string   `json:"sortBy,omitempty" form:"sortBy,omitempty"`
	SortOrder     string   `json:"sortOrder,omitempty" form:"sortOrder,omitempty"`
	Page          int      `json:"page,omitempty" form:"page,omitempty" in:"query=page,page_no,pageNo"`
	PageSize      int      `json:"pageSize,omitempty" form:"pageSize,omitempty" in:"query=pageSize,page_size,limit"`
	ID            string   `json:"id,omitempty" form:"id,omitempty"`
	IDs           []string `json:"ids,omitempty" form:"ids,omitempty"`
	IDsNot        []string `json:"idsNot,omitempty" form:"idsNot,omitempty"`
	DomainID      string   `json:"domainId,omitempty" form:"domainId,omitempty"`
	OrgID         string   `json:"orgId,omitempty" form:"orgId,omitempty"`
	GroupID       string   `json:"groupId,omitempty" form:"groupId,omitempty"`
	Aggregator    string   `json:"aggregator,omitempty" form:"aggregator,omitempty"`
	StartsWith    string   `json:"startsWith,omitempty" form:"startsWith,omitempty" in:"query=startsWith,starts_with"`
	Like          string   `json:"like,omitempty" form:"like,omitempty" in:"query=like,like"`
	ShowLinkedApp bool     `json:"showLinkedApp,omitempty" form:"showLinkedApp,omitempty" in:"query=showLinkedApp,show_linked_app"`
	EndsWith      string   `json:"endsWith,omitempty" form:"endsWith,omitempty"`
	Sorts         []*Sort  `json:"sorts,omitempty" form:"sorts,omitempty"`
	FromDate      string   `json:"fromDate,omitempty" form:"fromDate,omitempty"`
	ToDate        string   `json:"toDate,omitempty" form:"toDate,omitempty"`
	Fields        []string `json:"fields,omitempty" form:"fields,omitempty"`
}

// Sort :
type Sort struct {
	SortBy    string `json:"sortBy,omitempty"`
	SortOrder string `json:"sortOrder,omitempty"`
	Weight    int    `json:"weight,omitempty"`
}

type CowApplicationCriteriaVO struct {
	CriteriaVO
	Name            []string `json:"name,omitempty" in:"query=name,name[],Name,Name[]"`
	Version         []string `json:"version,omitempty" in:"query=version,version[],Version,Version[]"`
	Description     []string `json:"description,omitempty" in:"query=description,description[],Description,Description[]"`
	Type            []string `json:"type,omitempty" in:"query=type,Type,type[],Type[]"`
	Tags            []string `json:"tags,omitempty" in:"query=tags,Tags,tags[],Tags[]"`
	ApplicationType []string `json:"applicationType,omitempty" in:"query=application_type,application_type[],applicationType,applicationType[]"`
	AppType         string   `json:"appType,omitempty" in:"query=appType,AppType"`
}

type CowCredentialCriteriaVO struct {
	CriteriaVO
	Name        []string `json:"name,omitempty" in:"query=name,name[],Name,Name[]"`
	Version     []string `json:"version,omitempty" in:"query=version,version[],Version,Version[]"`
	Description []string `json:"description,omitempty" in:"query=description,description[],Description,Description[]"`
	Type        []string `json:"type,omitempty" in:"query=type,Type,type[],Type[]"`
	Tags        []string `json:"tags,omitempty" in:"query=tags,Tags,tags[],Tags[]"`
}

type CowRulesCriteriaVO struct {
	CriteriaVO
	Name          []string `json:"name,omitempty" in:"query=name,name[],Name,Name[]"`
	Apps          []string `json:"app,omitempty" in:"query=app,apps[],App,Apps[]"`
	Type          []string `json:"type,omitempty" in:"query=type,Type,type[],Type[]"`
	Tags          []string `json:"tags,omitempty" in:"query=tags,Tags,tags[],Tags[]"`
	IncludeReadMe bool     `json:"includeReadMe,omitempty" in:"query=include_read_me"`
}
