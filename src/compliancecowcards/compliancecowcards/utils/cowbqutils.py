import pandas as pd
from compliancecowcards.utils.cowbqschema_generator import SchemaGenerator
import json


def bq_schema_generator(df: pd.DataFrame):
    schema = None
    if not df.empty:
        jsonData = df.to_dict(orient="records")

        # records = [json.dumps(item) for item in jsonData]

        generator = SchemaGenerator(
            input_format="dict", keep_nulls=True, quoted_values_are_strings=True
        )

        schema_map, error_logs = generator.deduce_schema(jsonData)
        if error_logs is None or len(error_logs) == 0:
            schema = generator.flatten_schema(schema_map)
            schema = json.loads(json.dumps(schema))
    return schema


def configbuilder(df: pd.DataFrame):
    schema = bq_schema_generator(df)
    if schema:
        count = 0
        for item in schema:
            item["fieldName"] = item["name"]
            item["fieldDisplayName"] = item["name"]
            item["isFieldIndexed"] = False
            item["isFieldVisible"] = True
            item["isFieldVisibleForClient"] = True
            item["isRequired"] = True
            item["isRepeated"] = item["mode"] == "REPEATED"
            item["htmlElementType"] = item["type"]
            item["fieldDataType"] = item["type"]
            item["fieldOrder"] = count

            if "fields" in item:
                del item["fields"]

            count += 1
    return schema
