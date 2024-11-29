package main

// ValidateAzureAppConnector :
func (inst *TaskInstance) ValidateAzureAppConnector(inputs *UserInputs, outputs *Outputs) (err error) {

	outputs.IsValidated, err = inputs.Validate()
	if err != nil {
		outputs.ValidationMessage = err.Error()
	} else {
		outputs.ValidationMessage = "Credentials validated successfully"
	}
    
	return nil
}
