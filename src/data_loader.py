from pathlib import Path

import pandas as pd


def load_dataset(file_path: str) -> pd.DataFrame:
    """
    Load a CSV dataset and perform basic validation.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}"
        )

    if path.suffix.lower() != ".csv":
        raise ValueError(
            "The file must be a CSV file."
        )

    dataframe = pd.read_csv(
        path,
        low_memory=False
    )

    if dataframe.empty:
        raise ValueError(
            "The dataset contains no records."
        )

    dataframe.columns = [
        str(column).strip()
        for column in dataframe.columns
    ]

    return dataframe


if __name__ == "__main__":

    dataset_path = (
        "data/sample/sample_network_traffic.csv"
    )

    df = load_dataset(dataset_path)

    print("\nDataset loaded successfully!")

    print("\nNumber of rows:")
    print(df.shape[0])

    print("\nNumber of columns:")
    print(df.shape[1])

    print("\nColumn names:")
    print(df.columns.tolist())

    print("\nFirst five records:")
    print(df.head())