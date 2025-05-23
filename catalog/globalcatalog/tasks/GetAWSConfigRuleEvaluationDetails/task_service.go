package main

import (
	awsconnector "applicationtypes/awsappconnector"
	storage "applicationtypes/minio"
	"fmt"

	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/google/uuid"
)

// GetAWSConfigRuleEvaluationDetailsNew :
func (inst *TaskInstance) GetAWSConfigRuleEvaluationDetailsNew(inputs *UserInputs, outputs *Outputs) (err error) {

	var errorDetails []awsconnector.ErrorVO
	awsConnector := awsconnector.AWSAppConnector{UserDefinedCredentials: &inst.UserObject.App.UserDefinedCredentials,
		Region: inputs.Region}
	err = awsConnector.ValidateStruct(inputs)
	if err != nil {
		errorDetails = append(errorDetails, awsconnector.ErrorVO{Error: fmt.Sprintf("Error in input validation: " + err.Error())})
	}

	var outputRuleDetails []FinalOutput
	var outputConfigRulesList []*configservice.ConfigRule

	if len(errorDetails) == 0 {

		for _, region := range awsConnector.Region {
			inputConfigRules := &configservice.DescribeConfigRulesInput{}
			outputConfigRules, err := awsConnector.DescribeConfigRules(inputConfigRules, region)
			if err.Error != "" {
				errorDetails = append(errorDetails, err)
				continue
			}
			if len(outputConfigRules) == 0 {
				errorDetails = append(errorDetails, awsconnector.ErrorVO{Region: region, Error: "Rules are not enabled"})
				continue
			} else {
				outputConfigRulesList = append(outputConfigRulesList, outputConfigRules...)
			}
			for _, outputrule := range outputConfigRules {
				ruleid := outputrule.ConfigRuleName
				inputRule := &configservice.GetComplianceDetailsByConfigRuleInput{}
				inputRule.ConfigRuleName = ruleid
				outputRuleEvaluationDetail, err := awsConnector.GetConfigRuleEvaluationFunc(inputRule, region)
				if err.Error != "" {
					errorDetails = append(errorDetails, err)
					continue
				}
				outputRecord := FinalOutput{}
				for _, evaluationresult := range outputRuleEvaluationDetail {
					inputResource := configservice.BatchGetResourceConfigInput{}
					resource := configservice.ResourceKey{}
					outputRecord.EvaluationResult = evaluationresult
					resource.ResourceId = evaluationresult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId
					resource.ResourceType = evaluationresult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType
					inputResource.ResourceKeys = append(inputResource.ResourceKeys, &resource)
					outputResource, err := awsConnector.GetResourceConfiguration(&inputResource, region)
					if err != nil {
						errorDetails = append(errorDetails, awsconnector.ErrorVO{Region: region, Error: fmt.Sprintf("Error while fetching basic resource configuration: ResourceId - %v ResourceType - %v", *resource.ResourceId, *resource.ResourceType)})
						continue
					}
					if len(outputResource.BaseConfigurationItems) > 0 {
						if outputResource.BaseConfigurationItems[0].ResourceName != nil {
							outputRecord.AwsRegion = *(outputResource.BaseConfigurationItems[0].AwsRegion)
							outputRecord.ResourceName = *(outputResource.BaseConfigurationItems[0].ResourceName)
						}
					}
					outputRuleDetails = append(outputRuleDetails, outputRecord)
				}
			}
		}
	}

	if len(outputRuleDetails) > 0 {
		// Config rules evualuation list
		AWSConfigRuleEvaluationStatusWithTimeStamp := fmt.Sprintf("%v-%v%v", "AWSConfigRuleStatus", uuid.New().String(), ".json")
		outputs.AWSConfigRuleEvaluationStatusJSON, err = storage.UploadJSONFile(AWSConfigRuleEvaluationStatusWithTimeStamp, outputRuleDetails, inst.SystemInputs)
		if err != nil {
			return fmt.Errorf("Failed to upload aws config rule evaluation detail report  to minio: %v" + err.Error())
		}
	}

	if len(outputConfigRulesList) > 0 {
		// Config rules list
		AWSConfigRulesListWithTimeStamp := fmt.Sprintf("%v-%v%v", "AWSConfigRulesList", uuid.New().String(), ".json")
		outputs.AWSConfigRulesJSON, err = storage.UploadJSONFile(AWSConfigRulesListWithTimeStamp, outputConfigRulesList, inst.SystemInputs)
		if err != nil {
			return fmt.Errorf("Failed to upload aws config rules list to minio: %v" + err.Error())
		}
	}

	if errorDetails != nil {
		// Log file
		AuditFileWithTimeStamp := fmt.Sprintf("%v-%v%v", "LogFile", uuid.New().String(), ".json")
		outputs.LogFile, err = storage.UploadJSONFile(AuditFileWithTimeStamp, errorDetails, inst.SystemInputs)
		if err != nil {
			return fmt.Errorf("Failed to upload log file to minio: %v" + err.Error())
		}
	}

	// Meta data file
	if len(outputRuleDetails) > 0 {
		outputs.MetaDataFile, err = inst.uploadFieldMetaFile(outputRuleDetails, awsConnector)
		if err != nil {
			return fmt.Errorf("Failed to upload meta file to minio: %v" + err.Error())
		}
	}

	return nil
}

func (inst *TaskInstance) uploadFieldMetaFile(outputData []FinalOutput, awsConnector awsconnector.AWSAppConnector) (string, error) {
	if len(outputData) > 0 {
		fieldMetaData := awsConnector.CreateMetaFileData(outputData[0])
		metaFileNameWithUUID := fmt.Sprintf("%v-%v%v", "MetaDataFile", uuid.New().String(), ".json")
		outputFilePath, err := storage.UploadJSONFile(metaFileNameWithUUID, fieldMetaData, inst.SystemInputs)
		if err != nil {
			return "", fmt.Errorf("cannot upload meta file to minio: %w", err)
		}
		return outputFilePath, nil
	}
	return "", nil
}

type FinalOutput struct {
	EvaluationResult *configservice.EvaluationResult `json:"EvaluationResult"`
	ResourceName     string                          `json:"ResourceName"`
	AwsRegion        string                          `json:"AwsRegion"`
}
