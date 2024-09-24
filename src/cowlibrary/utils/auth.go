package utils

import (
	"cowlibrary/constants"
	"cowlibrary/vo"
	"encoding/json"
	"log"
	"net/http"
)

// GetSecurityContextFromHeader :
func GetSecurityContextFromHeader(header http.Header) (*vo.SecurityContext, error) {
	if header == nil {
		log.Println("header is nil")
		return nil, nil
	}
	securityContext := &vo.SecurityContext{}
	if authToken := header.Get(constants.Authorization); IsNotEmpty(authToken) {
		securityContext.AuthToken = authToken
		return securityContext, nil
	}

	securityContextString := header.Get(constants.SecurityContext)
	err := json.Unmarshal([]byte(securityContextString), securityContext)
	if err != nil {
		log.Println("Unmarshalling JSON failed:", err)
		return nil, err
	}
	return securityContext, nil
}

func SetSecurityContextInAdditionalInfo(additionalInfo *vo.AdditionalInfo, request *http.Request) error {

	if request != nil && additionalInfo != nil && request.Header != nil {
		securityCtx, err := GetSecurityContextFromHeader(request.Header)
		if err == nil && securityCtx != nil {
			additionalInfo.SecurityContext = securityCtx
			additionalInfo.InternalFlow = true
		}
	}

	return nil

}
