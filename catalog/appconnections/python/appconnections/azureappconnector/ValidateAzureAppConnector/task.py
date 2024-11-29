# This file is autogenerated. Modify as per your task needs.

from pathlib import Path
import sys

path_root = Path(__file__).parents[1]
sys.path.append(str(path_root))

import azureappconnector

from typing import overload
from compliancecowcards.structs import cards, cowvo
import json

class ValidateAzureAppConnector(cards.AbstractTask):

    def execute(self) -> dict:
        user_defined_credentials = None
        if self.task_inputs and self.task_inputs.user_inputs:
            user_defined_credentials = self.task_inputs.user_inputs

        azureappconnector_obj = azureappconnector.AzureAppConnector.from_dict(user_defined_credentials)

        is_valid, validation_message = azureappconnector_obj.validate()
        
        if validation_message and not isinstance(validation_message, str):
            validation_message = json.dumps(validation_message)
 
        response = {
            "IsValidated": is_valid,
            "ValidationMessage": "Credentials Validated Successfully" if is_valid else validation_message
        }

        return response