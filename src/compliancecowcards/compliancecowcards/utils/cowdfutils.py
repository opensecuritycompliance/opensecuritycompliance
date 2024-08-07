import pandas as pd
from typing import Tuple

def is_df_empty(df: any = None) -> bool:
    return not isinstance(df, pd.DataFrame) or df.empty

def df_to_dict(df: pd.DataFrame = None) -> Tuple[bytes, dict]:
    if is_df_empty(df):
        return None, { "error": "DataFrame is empty. Please ensure the DataFrame contains data." }
    df = cleanup_df(df)
    return df.to_dict(orient="records", index=False), None

def df_to_parquet(df: pd.DataFrame = None) -> Tuple[bytes, dict]:
    if is_df_empty(df):
        return None, { "error": "DataFrame is empty. Please ensure the DataFrame contains data." }
    df = cleanup_df(df)
    return df.to_parquet(index=False), None

def df_to_json(df: pd.DataFrame = None, ndjson: bool = False) -> Tuple[str, dict]:
    if is_df_empty(df):
        return None, { "error": "DataFrame is empty. Please ensure the DataFrame contains data." }
    df = cleanup_df(df)
    return df.to_json(orient="records", index=False, lines=ndjson), None

def df_to_ndjson(df: pd.DataFrame = None) -> Tuple[str, dict]:
    return df_to_json(df, ndjson=True)

def df_to_csv(df: pd.DataFrame = None) -> Tuple[str, dict]:
    if is_df_empty(df):
        return None, { "error": "DataFrame is empty. Please ensure the DataFrame contains data." }
    df = cleanup_df(df)
    return df.to_csv(index=False), None

def cleanup_df(df: pd.DataFrame):
    df.reset_index(drop=True, inplace=True)
    return df.map(lambda ele: None if isinstance(ele, dict) and ele == {} else ele)
    