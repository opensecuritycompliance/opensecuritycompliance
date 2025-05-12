package privacybisonconnector

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/har"
	"github.com/go-playground/validator/v10"
)

const (
	EpssAPI = "https://api.first.org/data/v1/epss?cve={{cve}}"
)

type NoCred struct {
	Dummy string `json:"dummy" yaml:"Dummy"`
}

type UserDefinedCredentials struct {
	NoCred NoCred `json:"noCred" yaml:"NoCred"`
}

type LinkedApplications struct {
}

type PrivacyBisonConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *PrivacyBisonConnector) Validate() (bool, error) {
	return true, nil
}

// INFO : You can implement your own implementation for the class
func (thisObj *PrivacyBisonConnector) ValidateStruct(s interface{}) error {
	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		return err
	}
	return nil
}

func (thisObj *PrivacyBisonConnector) GetCompanyNameFromHARFile(file []byte) (string, error) {
	var harfile = &HarVO{}
	siteUrl := ""
	err := json.Unmarshal(file, harfile)
	if err != nil {
		return "", fmt.Errorf("Invalid harfile structure - %v", err)
	}
	foundName := false

	var referer string
	var origin string
	var parserReferer string

	for _, entry := range harfile.Log.Entries {

		if entry.Initiator.Type == "other" {
			for _, header := range entry.Request.Headers {
				headerName := strings.ToLower(header.Name)
				if headerName == "origin" {
					foundName = true
					origin = header.Value
					break
				}
				if headerName == "referer" {
					referer = header.Value
				}
			}
			if foundName {
				break
			}
		} else if parserReferer == "" && entry.Initiator.Type == "parser" {
			for _, header := range entry.Request.Headers {
				headerName := strings.ToLower(header.Name)
				if headerName == "referer" {
					parserReferer = header.Value
				}
			}
		}

	}

	if origin != "" {
		siteUrl = origin
	} else {
		siteUrl = referer
	}

	if siteUrl == "" && parserReferer != "" {
		siteUrl = parserReferer
	}

	parsedUrl, err := url.Parse(siteUrl)
	if err == nil {
		host := parsedUrl.Host
		host = strings.Replace(host, "www.", "", -1)
		return host, nil
	} else if siteUrl != "" {
		siteUrl = strings.TrimPrefix(siteUrl, "http://")
		siteUrl = strings.TrimPrefix(siteUrl, "https://")
		siteUrl = strings.TrimPrefix(siteUrl, "www.")
		return siteUrl, nil

	} else {
		return "", nil
	}
}

// Exploit Prediction Scoring System (EPSS)
func (thisObj *PrivacyBisonConnector) GetEpssScoreForCVE(cveID string) (float64, string, string, error) {
	var epssScore float64
	var epssPercentile string
	var epssDate string
	epssAPI := strings.ReplaceAll(EpssAPI, "{{cve}}", cveID)
	epssResData := EPSSAPIResponse{}
	req, err := http.NewRequest("GET", epssAPI, nil)
	if err != nil {
		return epssScore, epssPercentile, epssDate, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return epssScore, epssPercentile, epssDate, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return epssScore, epssPercentile, epssDate, err
	}
	if res.StatusCode == 200 {
		err = json.Unmarshal(body, &epssResData)
		if err != nil {
			return epssScore, epssPercentile, epssDate, err
		}
		if len(epssResData.Data) > 0 {
			epssScoreFloat, err := strconv.ParseFloat(epssResData.Data[0].Epss, 64)
			if err != nil {
				return epssScore, epssPercentile, epssDate, err
			}
			epssPercentileFloat, err := strconv.ParseFloat(epssResData.Data[0].Percentile, 64)
			if err != nil {
				return epssScore, epssPercentile, epssDate, err
			}
			epssScore = epssScoreFloat * 100
			epssPercentile = fmt.Sprintf("%.2f", epssPercentileFloat*100)
			epssDate = epssResData.Data[0].Date
		}
	}
	return epssScore, epssPercentile, epssDate, nil
}

func (thisObj *PrivacyBisonConnector) GetCurrentTime() string {
	currentTime := time.Now().UTC()
	formattedTimestamp := currentTime.Format("2006-01-02T15:04:05.999Z")
	return formattedTimestamp
}

type EPSSAPIResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Access     string `json:"access"`
	Total      int    `json:"total"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Data       []struct {
		Cve        string `json:"cve"`
		Epss       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

type HarVO struct {
	Log *Log `json:"log"`
}

type Log struct {
	Version string       `json:"version"`
	Creator *har.Creator `json:"creator"`
	Browser *har.Creator `json:"browser,omitempty"` // Name and version info of used browser.
	Pages   []*har.Page  `json:"pages,omitempty"`   // List of all exported (tracked) pages. Leave out this field if the application does not support grouping by pages.
	Entries []*EntryVO   `json:"entries"`           // List of all exported (tracked) requests.
	Comment string       `json:"comment,omitempty"` // A comment provided by the user or the application.
}

type EntryVO struct {
	Pageref         string        `json:"pageref,omitempty"`         // Reference to the parent page. Leave out this field if the application does not support grouping by pages.
	StartedDateTime string        `json:"startedDateTime"`           // Date and time stamp of the request start (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD).
	Time            float64       `json:"time"`                      // Total elapsed time of the request in milliseconds. This is the sum of all timings available in the timings object (i.e. not including -1 values) .
	Request         *har.Request  `json:"request"`                   // Detailed info about the request.
	Response        *har.Response `json:"response"`                  // Detailed info about the response.
	Cache           *har.Cache    `json:"cache"`                     // Info about cache usage.
	Timings         *har.Timings  `json:"timings"`                   // Detailed timing info about request/response round trip.
	ServerIPAddress string        `json:"serverIPAddress,omitempty"` // IP address of the server that was connected (result of DNS resolution).
	Connection      string        `json:"connection,omitempty"`      // Unique ID of the parent TCP/IP connection, can be the client or server port number. Note that a port number doesn't have to be unique identifier in cases where the port is shared for more connections. If the port isn't available for the application, any other unique connection ID can be used instead (e.g. connection index). Leave out this field if the application doesn't support this info.
	Initiator       struct {
		Type string `json:"type"`
	} `json:"_initiator"`
	Comment string `json:"comment,omitempty"` // A comment provided by the user or the application.
}
