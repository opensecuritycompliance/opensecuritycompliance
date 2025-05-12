from typing import overload
from compliancecowcards.structs import cards
import pandas as pd
from io import StringIO
import pathlib
import pyarrow.parquet as pq
import pyarrow as pa
import os

from datetime import datetime


COMPLIANT = "COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
NOT_DETERMINED = "NOT_DETERMINED"


class Task(cards.AbstractTask):
    def execute(self) -> dict:
        compliance_pct, compliance_status, compliance_weight = 0, NOT_DETERMINED, 5

        response = {}
        if self.task_inputs.user_inputs and isinstance(self.task_inputs.user_inputs, dict):

            compliance_pct = self.task_inputs.user_inputs.get("CompliancePCT_", 0)

            compliance_status = self.task_inputs.user_inputs.get("ComplianceStatus_", "NOT_DETERMINED")
            final_evidence_df = pd.DataFrame()
            count = 1
            for key, val in self.task_inputs.user_inputs.items():
                if isinstance(val, str) and (val.startswith("http://" + os.getenv("MINIO_LOGIN_URL", "cowstorage:9000")) or (val.startswith("https") and ".amazon.com" in val)):
                    print("count :::", count)
                    count += 1
                    evidence_df = pd.DataFrame()
                    evidence_data_path = val
                    file_bytes, err = self.download_file_from_minio(file_url=evidence_data_path)

                    if err:
                        err = err.get("error", err)
                        return {"error": err.get("error", err)}

                    file_extension = pathlib.Path(evidence_data_path).suffix

                    if file_extension == ".parquet":
                        reader = pa.BufferReader(file_bytes)
                        evidence_df = pq.read_table(reader).to_pandas()
                    if file_extension == ".ndjson" or file_extension == ".json" or file_extension == ".csv":

                        message = file_bytes.decode("utf-8")
                        data = StringIO(message)
                        if file_extension == ".ndjson":
                            evidence_df = pd.read_json(data, lines=True, keep_default_dates=False, dtype=False)
                        elif file_extension == ".json":
                            evidence_df = pd.read_json(data, keep_default_dates=False, dtype=False)
                        else:
                            evidence_df = pd.read_csv(data)

                    if not evidence_df.empty:
                        if "ComplianceStatus" in list(evidence_df.columns):
                            if final_evidence_df.empty:
                                final_evidence_df = evidence_df
                            else:
                                final_evidence_df = pd.concat([final_evidence_df, evidence_df])

        print("final_evidence_df lenght :", len(final_evidence_df))

        if not final_evidence_df.empty:
            if "ComplianceStatus" in list(final_evidence_df.columns):
                filtered_df = final_evidence_df[final_evidence_df["ComplianceStatus"].isin([COMPLIANT, NON_COMPLIANT])]
                if not filtered_df.empty:
                    total_rows = len(filtered_df)
                    compliant_rows = len(filtered_df[filtered_df["ComplianceStatus"] == COMPLIANT])
                    if total_rows == 0 or compliant_rows == 0:
                        compliance_pct = 0
                    else:
                        compliance_pct = (compliant_rows / total_rows) * 100
                    compliance_status = COMPLIANT if compliance_pct == 100 else NON_COMPLIANT

        response = {"ComplianceStatus_": compliance_status, "CompliancePCT_": compliance_pct, "ComplianceWeight_": compliance_weight}

        return response
