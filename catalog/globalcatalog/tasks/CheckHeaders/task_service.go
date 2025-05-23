package main

import (
	cowStorage "applicationtypes/minio"
	"applicationtypes/privacybisonconnector"
	"cowlibrary/vo"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func (inst *TaskInstance) CheckHeaders(inputs *UserInputs, outputs *Outputs) (err error) {

	compliancePCT, complianceStatus := 0, "NON_COMPLIANT"
	defer func() {
		err = func() error {

			systemInputs := vo.SystemInputs{}
			systemInputsByteData, err := json.Marshal(inst.SystemInputs)
			if err != nil {
				return err
			}
			err = json.Unmarshal(systemInputsByteData, &systemInputs)
			if err != nil {
				return err
			}
			if outputs.ErrorDetails != nil {
				outputs.LogFile, err = cowStorage.UploadJSONFile(fmt.Sprintf("%v-%v%v", "log-", time.Now().Unix(), ".json"), outputs.ErrorDetails, systemInputs)
				if err != nil {
					return err
				}
			}

			outputs.CompliancePCT_ = compliancePCT
			outputs.ComplianceStatus_ = complianceStatus

			return nil
		}()
	}()
	var harFileBytes []byte
	har := &HAR{}
	if inputs.HarFile != "" {

		harFileBytes, err = cowStorage.DownloadFile(inputs.HarFile, inst.SystemInputs)
		if err != nil {
			outputs.ErrorDetails = err
			return nil
		}

		err = json.Unmarshal(harFileBytes, &har)
		if err != nil {
			outputs.ErrorDetails = err
			return nil
		}

	} else {
		outputs.ErrorDetails = errors.New("No valid HAR file present.")
		return nil
	}

	totalCount, passed := 0, 0
	privacybison := privacybisonconnector.PrivacyBisonConnector{}
	domain, err := privacybison.GetCompanyNameFromHARFile(harFileBytes)
	if err != nil {
		outputs.ErrorDetails = err
		return nil
	}

	check := func(uriInfo *URIInfo, header *Header, hs *HeaderStatus, headerName string, requrl string) {
		totalCount++
		log := &Log{Header: header, URL: uriInfo.URI, Host: uriInfo.Host, Attributes: make([]interface{}, 0)}
		stdLog := &StdLog{System: domain, Source: "compliancecow", ResourceID: uriInfo.URI, ResourceName: uriInfo.Host, ResourceType: "Header", ResourceURL: requrl, Header: header, EvaluatedTime: privacybison.GetCurrentTime()}
		hs.logs = append(hs.logs, log)
		hs.stdLogs = append(hs.stdLogs, stdLog)
		hs.do(uriInfo, header, log, stdLog)
		if log.Status == "passed" {
			passed++
		}
		if header == nil {
			log.Header = &Header{Name: strings.ToUpper(headerName)}
		}
	}
	headerStatuses := map[string]*HeaderStatus{}

	headerList := map[string]func(*URIInfo, *Header, *Log, *StdLog){
		"strict-transport-security":   inst.checkStrictTransportSecurity,
		"public-key-pins":             inst.checkPublicKeyPins,
		"expect-ct":                   inst.checkExpectCT,
		"x-frame-options":             inst.checkXFrameOptions,
		"access-control-allow-origin": inst.checkAccessControlAllowOrigin,
		"x-content-type-options":      inst.checkXContentTypeOptions,
		"referrer-policy":             inst.checkReferrerPolicy,
		"etag":                        inst.checkETag,
	}
	for k, v := range headerList {
		headerStatuses[k] = &HeaderStatus{
			logs:    make([]*Log, 0),
			do:      v,
			stdLogs: make([]*StdLog, 0),
		}
	}
	if har.Log != nil && har.Log.Entries != nil {
		for _, entry := range har.Log.Entries {
			url, err := url.Parse(entry.Request.URL)
			if err != nil {
				outputs.ErrorDetails = err
				return nil
			}
			uriInfo := &URIInfo{
				Host:     url.Host,
				URI:      url.Path,
				Response: entry.Response,
			}
			requrl := entry.Request.URL
			headers := map[string]*Header{}
			for _, header := range uriInfo.Response.Headers {
				headers[strings.ToLower(header.Name)] = header
			}
			for k, v := range headerStatuses {
				check(uriInfo, headers[k], v, k, requrl)
			}
		}
		defer func() {
			err = func() error {
				uploadFile := func(name, fileName string) (string, error) {
					headerStatus := headerStatuses[name]
					if headerStatus == nil {
						return "", nil
					}
					return cowStorage.UploadJSONFile(fileName, headerStatus.logs, inst.SystemInputs)
				}
				uploadStdFile := func(name, fileName string) (string, error) {
					headerStatus := headerStatuses[name]
					if headerStatus == nil {
						return "", nil
					}
					return cowStorage.UploadJSONFile(fileName, headerStatus.stdLogs, inst.SystemInputs)
				}

				outputs.StrictTransportSecurityLog, err = uploadFile("strict-transport-security", fmt.Sprintf("%v-%v%v", "StrictTransportSecurityLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.StdStrictTransportSecurityLog, err = uploadStdFile("strict-transport-security", fmt.Sprintf("%v-%v%v", "Std-StrictTransportSecurityLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.PublicKeyPinsLog, err = uploadFile("public-key-pins", fmt.Sprintf("%v-%v%v", "PublicKeyPinsLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.StdPublicKeyPinsLog, err = uploadStdFile("public-key-pins", fmt.Sprintf("%v-%v%v", "Std-PublicKeyPinsLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.ExpectCTLog, err = uploadFile("expect-ct", fmt.Sprintf("%v-%v%v", "ExpectCTLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.StdExpectCTLog, err = uploadStdFile("expect-ct", fmt.Sprintf("%v-%v%v", "Std-ExpectCTLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.XFrameOptionsLog, err = uploadFile("x-frame-options", fmt.Sprintf("%v-%v%v", "XFrameOptionsLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.StdXFrameOptionsLog, err = uploadStdFile("x-frame-options", fmt.Sprintf("%v-%v%v", "Std-XFrameOptionsLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.AccessControlAllowOriginLog, err = uploadFile("access-control-allow-origin", fmt.Sprintf("%v-%v%v", "AccessControlAllowOriginLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.StdAccessControlAllowOriginLog, err = uploadStdFile("access-control-allow-origin", fmt.Sprintf("%v-%v%v", "Std-AccessControlAllowOriginLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.XContentTypeOptionsLog, err = uploadFile("x-content-type-options", fmt.Sprintf("%v-%v%v", "XContentTypeOptionsLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.StdXContentTypeOptionsLog, err = uploadStdFile("x-content-type-options", fmt.Sprintf("%v-%v%v", "Std-XContentTypeOptionsLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.RefererPolicyLog, err = uploadFile("referrer-policy", fmt.Sprintf("%v-%v%v", "RefererPolicyLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.StdRefererPolicyLog, err = uploadStdFile("referrer-policy", fmt.Sprintf("%v-%v%v", "Std-RefererPolicyLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.ETagLog, err = uploadFile("etag", fmt.Sprintf("%v-%v%v", "ETagLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				outputs.StdETagLog, err = uploadStdFile("etag", fmt.Sprintf("%v-%v%v", "Std-ETagLog", time.Now().Unix(), ".json"))
				if err != nil {
					outputs.ErrorDetails = err
					return nil
				}
				return nil
			}()
		}()

		outputs.CompliancePCT_ = compliancePCT
		outputs.ComplianceStatus_ = complianceStatus

	}
	return nil
}

func (inst *TaskInstance) checkStrictTransportSecurity(uriInfo *URIInfo, header *Header, log *Log, stdLog *StdLog) {
	log.Status = "passed"
	stdLog.ComplianceStatus = "COMPLIANT"
	stdLog.ComplianceStatusReason = "The setting is compliant as it ensures HTTPS enforcement, protects against downgrade attacks, aligns with security best practices."
	stdLog.ValidationStatusCode = "STTS_P_VV"
	stdLog.ValidationStatusNotes = "Strict-Transport-Security header present with valid value"

	if header == nil {
		log.Status = "failed"
		log.StatusDescription = "This will leave the application vulnerable to man-in-the-middle and protocol downgrade attacks"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "This setting is non-compliant as a missing Strict-Transport-Security header results in vulnerability to downgrade attacks, potential exposure to MITM attacks."
		stdLog.ValidationStatusCode = "STTS_NP"
		stdLog.ValidationStatusNotes = "Strict-Transport-Security header not present"
		return
	}

	if strings.Contains(strings.ToLower(header.Value), "preload") {
		log.Status = "failed"
		log.StatusDescription = "HSTS Preload Option should not be present"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because preloading the HSTS policy irreversibly includes the domain in browser preload lists, which can be problematic for future changes or errors in policy."
		stdLog.ValidationStatusCode = "STTS_P_W_PR"
		stdLog.ValidationStatusNotes = "Strict-Transport-Security header present with preload"
		return
	}

}

func (inst *TaskInstance) checkPublicKeyPins(uriInfo *URIInfo, header *Header, log *Log, stdLog *StdLog) {

	if header != nil {
		log.Status = "failed"
		log.StatusDescription = "HTTP Public Key Pinning has been deprecated. Should not be used."
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "This setting is non-compliant as public key pins are deprecated and no longer recommended due to significant operational risks and potential security issues."
		stdLog.ValidationStatusCode = "PKP_P"
		stdLog.ValidationStatusNotes = "Public-Key-Pins header present"
		return
	}

	stdLog.ComplianceStatus = "COMPLIANT"
	stdLog.ComplianceStatusReason = "This setting is  compliant as public key pins are deprecated and no longer recommended due to significant operational risks and potential security issues."
	stdLog.ValidationStatusCode = "PKP_NP"
	stdLog.ValidationStatusNotes = "Public-Key-Pins header not present"
	log.Status = "passed"
}

func (inst *TaskInstance) checkExpectCT(uriInfo *URIInfo, header *Header, log *Log, stdLog *StdLog) {
	if header == nil {
		log.Status = "failed"
		log.StatusDescription = "Expect-CT header is missing"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because Expect-CT header is not present, which could lead to potential exposure to unauthorized certificates and reduced trust in issued certificates."
		stdLog.ValidationStatusCode = "ECT_NP"
		stdLog.ValidationStatusNotes = "Expect-CT header not present"
		return
	}

	if header.Value == "" {
		log.Status = "failed"
		log.StatusDescription = "Expect-CT header is missing"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because an empty Expect-CT header does not provide any policy enforcement or protection, leaving the site vulnerable to certificate-related attacks."
		stdLog.ValidationStatusCode = "ECT_P_EMT"
		stdLog.ValidationStatusNotes = "Expect-CT header present but is empty"
		return
	}

	value := strings.TrimSpace(header.Value)
	reportURI := ""
	for _, v := range strings.Split(value, ",") {
		if strings.Contains(v, "report-uri") {
			v = strings.Replace(v, "report-uri=", "", -1)
			v = strings.ReplaceAll(v, "\"", "")
			reportURI = strings.TrimSpace(v)
		}
	}
	if reportURI == "" {
		log.Status = "failed"
		log.StatusDescription = "Report uri should be present in Expect-CT header"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "This setting is non-compliant because an empty reportURI value in Expect-CT header leads to potential exposure to unauthorized certificates, reduced trust in issued certificates."
		stdLog.ValidationStatusCode = "ECT_P_RU_IV"
		stdLog.ValidationStatusNotes = "Expect-CT header present with invalid report-uri or empty"
		return
	}
	parsedReportURI, err := url.Parse(reportURI)
	if err != nil || parsedReportURI.Host == "" {
		log.Status = "failed"
		log.StatusDescription = "Invalid report uri in Expect-CT header"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "This setting is non-compliant because the Expect-CT header includes an invalid report-uri value, which leads to potential exposure to unauthorized certificates, reduced trust in issued certificates."
		stdLog.ValidationStatusCode = "ECT_P_RU_IV"
		stdLog.ValidationStatusNotes = "Expect-CT header present with invalid report-uri or empty"
		return
	}

	log.Status = "passed"
	stdLog.ComplianceStatus = "COMPLIANT"
	stdLog.ComplianceStatusReason = "The setting is compliant because the Expect-CT header includes a valid report-uri value. This enables the server to report compliance and any violations of the Certificate Transparency (CT) policy to the specified URI, enhancing security and trust in issued certificates."
	stdLog.ValidationStatusCode = "ECT_P_RU_VL"
	stdLog.ValidationStatusNotes = "Expect-CT header present with valid report-uri  value"
}

func (inst *TaskInstance) checkXFrameOptions(uriInfo *URIInfo, header *Header, log *Log, stdLog *StdLog) {
	log.Status = "passed"
	stdLog.ComplianceStatus = "COMPLIANT"
	stdLog.ComplianceStatusReason = "This setting is compliant as it helps mitigate clickjacking attacks by restricting framing to the same site."
	stdLog.ValidationStatusCode = "XFP_P_VV"
	stdLog.ValidationStatusNotes = "X-Frame-Options header present with valid value"

	if header == nil {
		log.Status = "failed"
		log.StatusDescription = "This will make the application vulnerable to clickjacking attacks"
		log.Remediation = "Add the X-Frame-Options header to responses to prevent clickjacking attacks"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "This setting is non-compliant as X-Frame-Options header is missing, which leads to vulnerablity to clickjacking attacks, potential iframe embedding on malicious sites."
		stdLog.ValidationStatusCode = "XFO_NP"
		stdLog.ValidationStatusNotes = "X-Frame-Options header not present"
		return
	}
	if strings.Contains(header.Value, "DENY") {
		log.Status = "failed"
		log.StatusDescription = "This will make the application vulnerable to clickjacking attacks"
		log.Remediation = "Add the X-Frame-Options header to responses to prevent clickjacking attacks"
		stdLog.ComplianceStatus = "COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is compliant because DENY  enhances security by completely preventing your web page from being framed by any other page, regardless of the origin."
		stdLog.ValidationStatusCode = "XFO_P_DY"
		stdLog.ValidationStatusNotes = "X-Frame-Options header present with value DENY"
		return
	}
	if strings.Contains(header.Value, "SAMEORIGIN") {
		log.Status = "failed"
		log.StatusDescription = "This will make the application vulnerable to clickjacking attacks"
		log.Remediation = "Add the X-Frame-Options header to responses to prevent clickjacking attacks"
		stdLog.ComplianceStatus = "COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is compliant because SAMEORIGIN enhances security by allowing your web page to be framed only by pages that originate from the same domain."
		stdLog.ValidationStatusCode = "XFO_P_SO"
		stdLog.ValidationStatusNotes = "X-Frame-Options header present with value SAMEORIGIN"
		return
	}

	if strings.Contains(header.Value, "ALLOW-FROM") && !strings.Contains(header.Value, uriInfo.Host) {
		log.Status = "failed"
		log.StatusDescription = "X-Frame-Option has 3rd party domain in ALLOW-FROM"
		log.Remediation = "Remove 3rd party domain from ALLOW-FROM attribute. Proxy on the server side, if required."
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because ALLOW-FROM <uri> allows embedding only from specific URIs, which can still pose security risks if the URI is not properly validated."
		stdLog.ValidationStatusCode = "XFO_P_AF"
		stdLog.ValidationStatusNotes = "X-Frame-Options header present with value ALLOW-FROM"
		return
	}

}

func (inst *TaskInstance) checkAccessControlAllowOrigin(uriInfo *URIInfo, header *Header, log *Log, stdLog *StdLog) {
	log.Status = "passed"
	stdLog.ComplianceStatus = "COMPLIANT"
	stdLog.ComplianceStatusReason = "The setting is compliant because the Access-Control-Allow-Origin header is properly configured to specify allowed origins. This helps ensure that cross-origin requests are handled securely without exposing resources to unauthorized origins."
	stdLog.ValidationStatusCode = "ACAO_P_VV"
	stdLog.ValidationStatusNotes = "Access-Control-Allow-Origin header present with valid value"

	if header == nil {
		log.Status = "failed"
		log.StatusDescription = "This will blocks cross-origin requests, causing CORS errors and limiting resource sharing"
		log.Remediation = "Add the Access-Control-Allow-Origin header to responses to enable cross-origin requests."
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because Access-Control-Allow-Origin header is missing and CORS requests are not properly configured, potentially exposing resources to unauthorized origins."
		stdLog.ValidationStatusCode = "ACAO_NP"
		stdLog.ValidationStatusNotes = "Access-Control-Allow-Origin header not present"
		return
	}

	if header.Value == "*" || header.Value == "null" || header.Value == "" {
		log.Status = "failed"
		log.StatusDescription = "Cannot be * or null. Opens up CORS attack"
		log.Remediation = "Prefer to handle through server side proxy. If required, codify for a specific https endpoint. If already used in Meta, carry that into the headers for consistency and maintainability."
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because the Access-Control-Allow-Origin header value is invalid, potentially allowing unauthorized origins to access resources, compromising security."
		stdLog.ValidationStatusCode = "ACAO_P_IV"
		stdLog.ValidationStatusNotes = "Access-Control-Allow-Origin header present with invalid value"
		return
	}

}

func (inst *TaskInstance) checkXContentTypeOptions(uriInfo *URIInfo, header *Header, log *Log, stdLog *StdLog) {
	if header == nil || header.Value == "" {
		log.Status = "failed"
		log.StatusDescription = "This will lead to MIME type security risks"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because X-Content-Type-Options header is missing, which allows browsers to perform MIME type sniffing, potentially increasing the risk of XSS attacks."
		stdLog.ValidationStatusCode = "XCTO_NP"
		stdLog.ValidationStatusNotes = "X-Content-Type-Options header not present"
		return
	}

	if header.Value != "nosniff" {
		log.Status = "failed"
		log.StatusDescription = "Invalid value in X-Content-Type-Options header"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because X-Content-Type-Options header allows browsers to perform MIME type sniffing, potentially increasing the risk of XSS attacks."
		stdLog.ValidationStatusCode = "XCTO_P_WO_NO_SNF"
		stdLog.ValidationStatusNotes = "X-Content-Type-Options header present without nosniff"
		return
	}

	stdLog.ComplianceStatus = "COMPLIANT"
	stdLog.ComplianceStatusReason = "The setting is compliant as X-Content-Type-Options header prevents MIME type sniffing, enhancing security against certain types of attacks such as XSS."
	stdLog.ValidationStatusCode = "XCTO_P_W_NO_SNF"
	stdLog.ValidationStatusNotes = "X-Content-Type-Options header present with nosniff"
	log.Status = "passed"
}

func (inst *TaskInstance) checkReferrerPolicy(uriInfo *URIInfo, header *Header, log *Log, stdLog *StdLog) {
	log.Status = "passed"
	stdLog.ComplianceStatus = "COMPLIANT"
	stdLog.ComplianceStatusReason = "The setting is compliant because a valid Referrer-Policy header is present, indicating a specified policy for handling referrer information, enhancing security and privacy."
	stdLog.ValidationStatusCode = "RP_P_W_VV"
	stdLog.ValidationStatusNotes = "Referrer-Policy header present with valid value"

	if header == nil || header.Value == "" {
		log.Status = "failed"
		log.StatusDescription = "This will leak potentially-private information to insecure origins"
		log.Remediation = "Set appropriate value for header"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because the absence of the Referrer-Policy header allows browsers to use their default behavior for handling referrer information. This default behavior may not provide sufficient control over referrer headers, potentially exposing sensitive information."
		stdLog.ValidationStatusCode = "RP_NP"
		stdLog.ValidationStatusNotes = "Referrer-Policy header not present"
		return
	}

	if header.Value == "unsafe-url" {
		log.Status = "failed"
		log.StatusDescription = "This will leak potentially-private information to insecure origins"
		log.Remediation = "Remove Referrer-Policy header or set appropriate value for header"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because unsafe-url allows sending referrer information to URLs that may not be trusted. This can expose sensitive data to potentially malicious entities, undermining security and privacy measures."
		stdLog.ValidationStatusCode = "RP_P_W_US"
		stdLog.ValidationStatusNotes = "Referrer-Policy header present with value unsafe-url"
		return
	}
}

func (inst *TaskInstance) checkETag(uriInfo *URIInfo, header *Header, log *Log, stdLog *StdLog) {
	log.Status = "passed"
	stdLog.ComplianceStatus = "COMPLIANT"
	stdLog.ComplianceStatusReason = "The setting is compliant as the ETag header is present with a strong entity tag value, supporting efficient resource validation and caching."
	stdLog.ValidationStatusCode = "ETG_P_VL"
	stdLog.ValidationStatusNotes = "ETag header present and is valid"

	if header == nil {
		log.Status = "failed"
		log.StatusDescription = "This will reduce caching efficiency and resource validation reliability"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because the ETag header is not present, potentially hindering caching mechanisms and resource validation efficiency."
		stdLog.ValidationStatusCode = "ETG_NP"
		stdLog.ValidationStatusNotes = "ETag header not present"
		return
	}

	if header.Value[0] == 'W' || header.Value[0] == 'w' {
		log.Status = "failed"
		log.StatusDescription = "E-Tag header using weak tags"
		stdLog.ComplianceStatus = "NON_COMPLIANT"
		stdLog.ComplianceStatusReason = "The setting is non-compliant because the ETag header is present with a weak entity tag value, which may not provide adequate security or reliability for caching."
		stdLog.ValidationStatusCode = "ETG_P_WK"
		stdLog.ValidationStatusNotes = "Etag header present and is weak"
		return
	}
}

// URIInfo :
type URIInfo struct {
	Host     string
	URI      string
	Headers  []*Header
	Response *Response
}

// Response :
type Response struct {
	Status  int
	Headers []*Header
	Content ResponseContent
}

// ResponseContent :
type ResponseContent struct {
	Compression int
	MimeType    string
	Size        int
	Text        string
}

// KeyValue :
type KeyValue struct {
	Name  string
	Value string
}

// Header :
type Header KeyValue

// HeaderStatus :
type HeaderStatus struct {
	logs      []*Log
	stdLogs   []*StdLog
	failCount int
	do        func(*URIInfo, *Header, *Log, *StdLog)
}

// Log :
type Log struct {
	Host              string
	URL               string
	Header            *Header
	Status            string
	StatusDescription string
	Remediation       string
	Info              string
	Warning           string
	Error             string
	Attributes        []interface{}
	Rules             []interface{}
	Category          string
}
type StdLog struct {
	System                 string
	Source                 string
	ResourceID             string
	ResourceType           string
	ResourceName           string
	ResourceURL            string
	Header                 *Header
	ComplianceStatus       string
	ComplianceStatusReason string
	ValidationStatusCode   string
	ValidationStatusNotes  string
	EvaluatedTime          string
	UserAction             string
	ActionStatus           string
	ActionResponseURL      string
}

// HAR :
type HAR struct {
	Log *struct {
		Entries []*struct {
			StartedDateTime time.Time `json:"startedDateTime"`
			Request         *struct {
				Method  string    `json:"method"`
				URL     string    `json:"url"`
				Headers []*Header `json:"headers"`
			} `json:"request"`
			Response *Response `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}
