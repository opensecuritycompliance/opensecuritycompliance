import pandas as pd
from typing import Tuple
import numpy as np
from dateutil import parser
import json
from datetime import datetime
from compliancecowcards.utils import cowconstants


def is_df_empty(df: any = None) -> bool:
    return not isinstance(df, pd.DataFrame) or df.empty


def df_to_dict(df=pd.DataFrame()):
    data = None
    if not df.empty:
        data = json.dumps(df.to_dict(orient="records"),
                          default=dataframeserializer)
        data = json.loads(data)
    return data


def dataframeserializer(obj):
    try:
        if obj is None or obj is pd.NaT or pd.isna(obj):
            return None
    except Exception:
        pass

    if isinstance(obj, np.ndarray):
        return obj.tolist()

    if isinstance(obj, str) and is_date(obj):
        obj = parser.parse(obj)
        return obj.strftime(cowconstants.DateTimeFormat)

    if isinstance(obj, datetime):
        return obj.strftime(cowconstants.DateTimeFormat)
    return str(obj)


def is_date(string, fuzzy=False):
    """
    Return whether the string can be interpreted as a date.

    :param string: str, string to check for date
    :param fuzzy: bool, ignore unknown tokens in string if True
    """
    try:
        parser.parse(string, fuzzy=fuzzy)
        return True

    except ValueError:
        return False


def df_to_parquet(df: pd.DataFrame = None) -> Tuple[bytes, dict]:
    if is_df_empty(df):
        return None, {"error": "DataFrame is empty. Please ensure the DataFrame contains data."}
    df = cleanup_df(df)
    return df.to_parquet(index=False), None


def df_to_json(df: pd.DataFrame = None, ndjson: bool = False) -> Tuple[str, dict]:
    if is_df_empty(df):
        return None, {"error": "DataFrame is empty. Please ensure the DataFrame contains data."}
    df = cleanup_df(df)
    return df.to_json(orient="records", index=False, lines=ndjson), None


def df_to_ndjson(df: pd.DataFrame = None) -> Tuple[str, dict]:
    return df_to_json(df, ndjson=True)


def df_to_csv(df: pd.DataFrame = None) -> Tuple[str, dict]:
    if is_df_empty(df):
        return None, {"error": "DataFrame is empty. Please ensure the DataFrame contains data."}
    df = cleanup_df(df)
    return df.to_csv(index=False), None


def cleanup_df(df: pd.DataFrame):
    df.reset_index(drop=True, inplace=True)
    return df.map(lambda ele: None if isinstance(ele, dict) and ele == {} else ele)
