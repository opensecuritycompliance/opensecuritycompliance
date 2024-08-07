package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/go-resty/resty/v2"
	"github.com/iancoleman/strcase"
	"github.com/kyokomi/emoji"
	"github.com/olekukonko/tablewriter"
	cp "github.com/otiai10/copy"

	"cowlibrary/constants"
	"cowlibrary/utils"
	"cowlibrary/vo"
)

func WriteDashboardFiles(dashboardName, dashboardsPath string) error {
	dashboardPath := filepath.Join(dashboardsPath, strcase.ToCamel(dashboardName))
	err := os.MkdirAll(dashboardPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create dashboard folder at %s", dashboardPath)
	}
	fileNames := []string{constants.CowTemplateJinjaFile, constants.CowDashBoardJSFile, constants.MetaJsonFile, constants.MarkDownFile}
	fileContents := []string{constants.CowTemplateJinja, constants.CowDashBoardJS, constants.DashBoardMetaJson, constants.MarkDown}

	for i, fileName := range fileNames {
		if err := os.WriteFile(filepath.Join(dashboardPath, fileName), []byte(fileContents[i]), os.ModePerm); err != nil {
			return fmt.Errorf("failed to write %s at %v, error:%h", fileName, dashboardPath, err)
		}
	}
	pythonFile := strings.ReplaceAll(constants.SampleDashboard, "{{DashboardClassName}}", utils.TitleFormat(dashboardName))
	pythonFile = strings.ReplaceAll(pythonFile, constants.ModuleName, strings.ToLower(dashboardName))
	if err := os.WriteFile(filepath.Join(dashboardPath, strings.ToLower(strings.ReplaceAll(dashboardName, " ", ""))+".py"), []byte(pythonFile), os.ModePerm); err != nil {
		return err
	}

	return nil
}

func InitDashboard(dashboardName, dashboardsPath string, reportDetails []*vo.ReportInputVO, additionalInfo *vo.AdditionalInfo) error {
	dashboardName = strcase.ToCamel(dashboardName)
	dashboardPath := filepath.Join(dashboardsPath, dashboardName)
	err := WriteDashboardFiles(dashboardName, dashboardsPath)
	if err != nil {
		return err
	}
	err = InitReport(dashboardPath, reportDetails, additionalInfo)
	if err != nil {
		return err
	}
	comments := []string{"# ADD_IMPORTS_HERE", "# INITIATE_REPORTS_HERE", "# MAP_CHARTS_HERE", "# MAP_PLOTS_HERE", "# ADD_PLOTS"}
	err = utils.RemoveCommentsFromPythonFiles(dashboardPath, comments)
	if err != nil {
		return err
	}
	return nil
}

func UpdatePythonFile(dashboardPath, reportName string) error {
	moduleName := strings.ToLower(reportName)
	className := utils.TitleFormat(reportName)
	filePath := filepath.Join(dashboardPath, strings.ToLower(filepath.Base(dashboardPath))+".py")
	if utils.IsFileNotExist(filePath) {
		return fmt.Errorf("%s is an invalid path", filePath)
	}
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	replacer := strings.NewReplacer("# ADD_IMPORTS_HERE", fmt.Sprintf("from %s import %v \n# ADD_IMPORTS_HERE", moduleName, moduleName),
		"# INITIATE_REPORTS_HERE", fmt.Sprintf("self.%s = %s.%v(req_obj=self.req_obj, kwargs=self.kwargs) \n        # INITIATE_REPORTS_HERE", moduleName, moduleName, className),
		"# MAP_CHARTS_HERE", fmt.Sprintf(`"%s": self.%s.%s(),`+"\n            # MAP_CHARTS_HERE", moduleName, moduleName, "dashboard_chart"),
		"# MAP_PLOTS_HERE", fmt.Sprintf(`"%s": self.%s.%v(is_plot_return_call),`+"\n                # MAP_PLOTS_HERE", moduleName, moduleName, "dashboard_chart"),
		"# ADD_PLOTS", fmt.Sprintf(` self.%s.%v(is_plot_return_call), `+"\n                # ADD_PLOTS", moduleName, "dashboard_chart"),
	)
	modifiedContent := replacer.Replace(string(fileContent))

	err = os.WriteFile(filePath, []byte(modifiedContent), os.ModePerm)

	return err
}

func UpdateDashboardJinja(dashboardPath, reportName string) error {
	cowTempJinjaReport := strings.ReplaceAll(constants.CowTemplateJinjaReport, constants.ModuleName, strings.ToLower(reportName))
	cowTempJinjaReport = strings.ReplaceAll(cowTempJinjaReport, constants.ClassName, utils.TitleFormat(reportName))
	filePath := filepath.Join(dashboardPath, "cow_template.jinja")
	if utils.IsFileNotExist(filePath) {
		return fmt.Errorf("%s is an invalid path", filePath)
	}
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	replacer := strings.NewReplacer("{# update the charts here #}", cowTempJinjaReport+"\n {# update the charts here #}")
	modifiedContent := replacer.Replace(string(fileContent))

	err = os.WriteFile(filePath, []byte(modifiedContent), os.ModePerm)
	return err
}
func determineFileContent(reportTemplate, reportName string) string {
	switch reportTemplate {
	case "pie":
		return constants.PieChartPY
	case "bar":
		return constants.BarChartPY
	default:
		fileContent := constants.DefaultReportPY
		fileContent = strings.ReplaceAll(fileContent, constants.PackageName, strings.ToLower(reportName))
		return fileContent
	}
}

func WriteReportFiles(dashboardPath, reportName, reportTemplate string) error {
	reportPath := filepath.Join(dashboardPath, strings.ToLower(reportName))
	err := os.MkdirAll(reportPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create %s at %v", reportName, dashboardPath)
	}
	fileNames := []string{constants.CowTemplateJinjaFile, constants.MarkDownFile, constants.MetaJsonFile}
	fileContents := []string{constants.ReportCowTemplateJinja, constants.MarkDown, constants.ReportMetaJson}

	for i, fileName := range fileNames {
		if err := os.WriteFile(filepath.Join(reportPath, fileName), []byte(fileContents[i]), os.ModePerm); err != nil {
			return err
		}
	}
	fileContent := determineFileContent(reportTemplate, reportName)
	fileContent = strings.ReplaceAll(fileContent, constants.ClassName, utils.TitleFormat(reportName))
	fileContent = strings.ReplaceAll(fileContent, constants.ModuleName, strings.ToLower(reportName))

	if err := os.WriteFile(filepath.Join(reportPath, strings.ToLower(reportName)+".py"), []byte(fileContent), os.ModePerm); err != nil {
		return err
	}
	return nil
}

func InitReport(dashboardPath string, reportDetails []*vo.ReportInputVO, additionalInfo *vo.AdditionalInfo) error {
	for _, report := range reportDetails {
		report.Name = strcase.ToCamel(report.Name)
		err := WriteReportFiles(dashboardPath, strings.ReplaceAll(report.Name, " ", ""), report.Template)
		if err != nil {
			return err
		}
		err = UpdatePythonFile(dashboardPath, report.Name)
		if err != nil {
			return err
		}
		err = UpdateDashboardJinja(dashboardPath, report.Name)
		if err != nil {
			return err
		}

	}
	return nil
}

func readMetaJsonFile(filePath string) (map[string]interface{}, error) {
	metaJson, err := os.ReadFile(filepath.Join(filePath, "_meta.json"))
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	err = json.Unmarshal(metaJson, &data)
	if err != nil {
		return nil, fmt.Errorf("error parsing _meta.json: %s", err)
	}

	return data, nil
}

func updateFilters(data map[string]interface{}, name, filePath string) {
	reportsFilters, ok := data["reportsFilters"].([]interface{})
	if !ok {
		fmt.Printf("reportsFilters missing in %s\n", filePath)
		return
	}

	for _, reportFilter := range reportsFilters {
		filter, ok := reportFilter.(map[string]interface{})
		if !ok {
			fmt.Println("invalid reportFilter data structure in _meta.json")
			continue
		}

		filter["className"] = utils.TitleFormat(name)
		filter["packageName"] = strings.ToLower(name)
		filter["moduleName"] = strings.ToLower(name)
	}
}

func UpdateMetaJson(filePath string) error {

	name := filepath.Base(filePath)
	// TODO ues utils.ReadJson
	data, err := readMetaJsonFile(filePath)
	if err != nil {
		return fmt.Errorf("error un-marshalling _meta.json,%s", err)
	}
	updateFilters(data, name, filePath)
	updatedJson, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return fmt.Errorf("error marshalling updated _meta.json,%s", err)
	}
	err = os.WriteFile(filepath.Join(filePath, "_meta.json"), updatedJson, os.ModePerm)
	if err != nil {
		return err
	}
	subDirs, err := os.ReadDir(filePath)
	if err != nil {
		return err
	}
	for _, subDir := range subDirs {
		if subDir.IsDir() {
			err := UpdateMetaJson(filepath.Join(filePath, subDir.Name()))
			if err != nil {
				fmt.Printf("Error updating _meta.json files in %s: %v\n", filepath.Join(filePath, subDir.Name()), err)
			}
		}
	}
	return nil
}

func ZipDashboardDir(dashboardName, dashboardsPath string, additionalInfo *vo.AdditionalInfo) (exportedData *vo.ExportedData, err error) {

	if utils.IsEmpty(additionalInfo.DownloadsPath) {
		additionalInfo.DownloadsPath = additionalInfo.PolicyCowConfig.PathConfiguration.DownloadsPath
	}
	dashboardPath := filepath.Join(dashboardsPath, dashboardName)
	tempDir, err := os.MkdirTemp("", "dashboard")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)
	err = cp.Copy(dashboardPath, filepath.Join(tempDir, dashboardName))
	if err != nil {
		return nil, err
	}

	err = UpdateMetaJson(filepath.Join(tempDir, dashboardName))
	if err != nil {
		return nil, errors.New("meta.json updation failed")
	}
	err = utils.ZIPFilesWithCommands(tempDir, additionalInfo.DownloadsPath, dashboardName)
	if err != nil {
		return exportedData, err
	}
	exportedData = &vo.ExportedData{FilePath: filepath.Join(additionalInfo.DownloadsPath, dashboardName)}

	return exportedData, nil
}

func GetValidationErrors(client *resty.Client, cowAPIEndpoint string, headerMap map[string]string, fileHash string) (*vo.ValidationFile, error) {
	var errorFile *vo.ValidationFile
	validationErrURL := fmt.Sprintf("%s/url-hash/download/%v", cowAPIEndpoint, fileHash)
	_, err := client.R().SetHeaders(headerMap).SetResult(errorFile).Get(validationErrURL)
	if err != nil {
		return nil, err
	}

	return errorFile, nil
}

func ValidateDashboard(client *resty.Client, additionalInfo *vo.AdditionalInfo, headerMap map[string]string, fileBytes []byte) error {
	cowAPIEndpoint := utils.GetCowAPIEndpoint(additionalInfo)
	validationURL := fmt.Sprintf("%s/v2/userdefined-report-card/validate-cards", cowAPIEndpoint)

	requestData := map[string]interface{}{
		"file_bytes": fileBytes,
	}
	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond)
	s.Prefix = "validating ..."
	s.Start()

	validationResponse := &vo.ValidationResponse{}
	_, err := client.R().SetHeaders(headerMap).SetBody(requestData).SetError(validationResponse).Post(validationURL)
	if err != nil {
		return err
	}
	s.Stop()
	if utils.IsNotEmpty(validationResponse.FileHash) && validationResponse.IsFileContainsIssues {
		errorFile, err := GetValidationErrors(client, cowAPIEndpoint, headerMap, validationResponse.FileHash)
		if err != nil {
			return err
		}

		errorMessages := []*vo.ValidationError{}
		err = json.Unmarshal([]byte(errorFile.FileContent), &errorMessages)
		if err != nil {
			return err
		}

		DrawErrorSummaryTable(errorMessages)
		return errors.New("dashboard validation failed")
	}

	return nil
}

func PublishDashboard(dashboardName, dashboardsPath, category string, additionalInfo *vo.AdditionalInfo) error {

	exportedData, err := ZipDashboardDir(dashboardName, dashboardsPath, additionalInfo)
	if err != nil {
		return err
	}
	compressedFilePath := fmt.Sprintf("%s.%s", exportedData.FilePath, "zip")
	if utils.IsFileNotExist(compressedFilePath) {
		return fmt.Errorf("%s does not exist", compressedFilePath)
	}
	headerMap, err := utils.GetAuthHeader(additionalInfo)
	if err != nil {
		return err
	}
	client := resty.New()
	cowAPIEndpoint := utils.GetCowAPIEndpoint(additionalInfo)
	errorData := json.RawMessage{}
	fileBytes, err := os.ReadFile(compressedFilePath)
	if err != nil {
		return err
	}
	err = ValidateDashboard(client, additionalInfo, headerMap, fileBytes)
	if err != nil {
		return err
	}
	defer os.Remove(compressedFilePath)

	categoryID, err := utils.GetCategoryID(client, additionalInfo, headerMap, category)
	if err != nil {
		return err
	}

	workFlowID, err := utils.GetWorkflowID(client, additionalInfo, headerMap)
	if err != nil {
		return err
	}
	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond) // Build our new spinner
	s.Prefix = "Publishing ..."
	s.Start()

	dashboardPublisher := &vo.DashboardPublisherVO{WorkflowConfigId: workFlowID}
	dashboardPublisher.Input = additionalInfo.DashboardVO
	dashboardPublisher.Input.Name = dashboardName
	dashboardPublisher.Input.FileBytes = fileBytes
	dashboardPublisher.Input.Level = "user"
	dashboardPublisher.Input.Description = additionalInfo.DashboardVO.Description
	dashboardPublisher.Input.CategoryID = categoryID
	publishUrl := fmt.Sprintf("%s/v1/workflow-instances", cowAPIEndpoint)
	resp, err := client.R().SetHeaders(headerMap).SetBody(dashboardPublisher).SetError(&errorData).Post(publishUrl)

	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusCreated {
		s.Stop()
		return fmt.Errorf("cannot publish the dashboard,err:%s", errorData)
	}
	s.Stop()
	emoji.Println(":megaphone: dashboard has been published!!! :party_popper::partying_face::party_popper:")
	return nil
}

func DrawErrorSummaryTable(errorMessages []*vo.ValidationError) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Message Type", "Message", "Desctription"})
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor})
	for _, errorMessage := range errorMessages {
		row := []string{errorMessage.MessageType, errorMessage.Message, errorMessage.Description}
		table.Append(row)
	}
	table.Render()
}
