package utils

import (
	"errors"
	"fmt"

	resty "github.com/go-resty/resty/v2"

	"cowlibrary/vo"
)

func GetCategoryID(client *resty.Client, additionalInfo *vo.AdditionalInfo, headerMap map[string]string, category string) (string, error) {

	insightCategoryURL := fmt.Sprintf("%s/v1/get-insightscategory", GetCowAPIEndpoint(additionalInfo))
	insightCategoryRes := &struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}{}

	_, err := client.R().SetHeaders(headerMap).SetQueryParam("name", category).SetResult(insightCategoryRes).Get(insightCategoryURL)
	if err != nil {
		return "", err
	}

	if len(insightCategoryRes.Items) > 0 {
		return insightCategoryRes.Items[0].ID, nil
	}

	return CreateInsightCategory(client, additionalInfo, headerMap, category)
}

func CreateInsightCategory(client *resty.Client, additionalInfo *vo.AdditionalInfo, headerMap map[string]string, category string) (string, error) {
	insightCategory := &vo.InsightCategory{
		Name:        category,
		Description: category,
		Level:       "user",
	}

	insightResp := &vo.InsightCategory{}
	insightCategoryURL := fmt.Sprintf("%s/v2/insights-category", GetCowAPIEndpoint(additionalInfo))

	_, err := client.R().SetHeaders(headerMap).SetBody(insightCategory).SetResult(insightResp).Post(insightCategoryURL)
	if err != nil {
		return "", fmt.Errorf("category creation failed: %s", err)
	}

	return insightResp.ID, nil
}

func GetWorkflowID(client *resty.Client, additionalInfo *vo.AdditionalInfo, headerMap map[string]string) (string, error) {
	workFlowName := "Upload report card"
	workFlowURL := fmt.Sprintf("%s/v1/workflow-configs", GetCowAPIEndpoint(additionalInfo))
	workFlowRes := &struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}{}

	_, err := client.R().SetHeaders(headerMap).SetQueryParam("name", workFlowName).SetResult(workFlowRes).Get(workFlowURL)
	if err != nil {
		return "", err
	}

	if len(workFlowRes.Items) > 0 {
		return workFlowRes.Items[0].ID, nil
	}

	return "", errors.New("failed to fetch workflow ID")
}
