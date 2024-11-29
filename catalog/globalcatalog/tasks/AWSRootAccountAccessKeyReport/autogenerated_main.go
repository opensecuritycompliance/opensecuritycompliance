// This file is autogenerated. Please do not modify
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"cowlibrary/constants"
)

func handlePanic() {
	r := recover()
	if r != nil {
		os.WriteFile("logs.txt", debug.Stack(), os.ModePerm)
		os.WriteFile("task_output.json", []byte(`{"error":"`+fmt.Sprintf("%v, %s", r, "Please review the stack trace in the logs.txt file within the task.")+`"}`), os.ModePerm)
	}
}

func main() {
	defer handlePanic()
	inst := new(TaskInstance)

	taskInput := &TaskInputs{}
	taskOutput := &TaskOutputs{Outputs: &Outputs{}}
	errorOutput := make(map[string]string)

	inputObj := &TaskInputs{}
	if _, err := os.Stat("inputs.yaml"); err == nil {
		byts, err := os.ReadFile("inputs.yaml")
		if err == nil {
			err = yaml.Unmarshal(byts, inputObj)
			if err != nil {
				taskInputObj := &TaskInputsV2{}
				err = yaml.Unmarshal(byts, taskInputObj)
				if err == nil {
					inputObj.SystemInputs = taskInputObj.SystemInputs
					inputObj.UserInputs = taskInputObj.UserInputs
					inputObj.FromDate_, _ = time.Parse("2006-01-02", taskInputObj.FromDate_)
					inputObj.ToDate_, _ = time.Parse("2006-01-02", taskInputObj.ToDate_)
				}
			}
		}
		taskInputByts, err := json.Marshal(inputObj)
		if err != nil {
			return
		}
		taskInputFilePath := "task_input.json"
		taskInputByts = []byte(os.ExpandEnv(string(taskInputByts)))
		err = os.WriteFile(taskInputFilePath, taskInputByts, os.ModePerm)
		if err != nil {
			errorOutput["error"] = err.Error()
			return
		}
	}

	taskInputFile := ""
	flag.StringVar(&taskInputFile, "f", "task_input.json", "task input file path")
	flag.Parse()

	taskOutputFile := ""
	i := strings.LastIndex(taskInputFile, "/")
	if i != -1 {
		taskOutputFile = taskInputFile[:i+1]
	}
	taskOutputFile += "task_output.json"

	err := readFromFile(taskInputFile, taskInput)
	if err != nil {
		errorOutput["error"] = err.Error()
		writeToFile(taskOutputFile, errorOutput)
		return
	}

	// INFO : Added for unit testing
	if len(taskInput.SystemObjects) == 0 {
		defaultSystemObjectByts := []byte(os.ExpandEnv(string(constants.SystemObjects)))
		json.Unmarshal(defaultSystemObjectByts, &taskInput.SystemObjects)
		metaDataTemplate := &MetaDataTemplate{}
		metaDataTemplate.ControlID = uuid.New().String()
		metaDataTemplate.PlanExecutionGUID = uuid.New().String()
		metaDataTemplate.RuleGUID = uuid.New().String()
		metaDataTemplate.RuleTaskGUID = uuid.New().String()
		taskInput.MetaData = metaDataTemplate
	}

	inst.SystemInputs = &(taskInput.SystemInputs)
	err = inst.AWSRootAccountAccessKeyReport(taskInput.UserInputs, taskOutput.Outputs)
	if err != nil {
		errorOutput["error"] = err.Error()
		writeToFile(taskOutputFile, errorOutput)
		return
		// panic(err.Error())
	}
	writeToFile(taskOutputFile, taskOutput)
}

func readFromFile(fileName string, dest interface{}) error {

	jsonFile, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer jsonFile.Close()
	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, dest)
	if err != nil {
		return err
	}
	return nil
}

func writeToFile(fileName string, data interface{}) error {
	payload, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}
	err = os.WriteFile(fileName, payload, 0644)
	if err != nil {
		return err
	}
	return nil
}

type TaskInstance struct {
	*SystemInputs
}
