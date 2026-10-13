from pathlib import Path
import pandas as pd

DATA_DIR = Path("data/raw")


def inspect_dataset(file_path: Path) -> None:
    print("\n" + "=" * 80)
    print(f"FILE: {file_path.name}")
    print("=" * 80)

    # Read only the header and a small sample first.
    sample = pd.read_csv(file_path, nrows=1000, low_memory=False)

    # Normalise whitespace in column names.
    sample.columns = sample.columns.astype(str).str.strip()

    print(f"\nColumns: {len(sample.columns)}")
    print("\nColumn names:")
    print(sample.columns.tolist())

    print("\nSample data types:")
    print(sample.dtypes.to_string())

    print("\nMissing values in the first 1,000 rows:")
    print(sample.isna().sum().sort_values(ascending=False).head(10))

    print("\nDuplicate rows in the sample:")
    print(sample.duplicated().sum())

    label_candidates = [
        column
        for column in sample.columns
        if column.lower() in {"label", "class", "attack"}
    ]

    if label_candidates:
        label_column = label_candidates[0]
        print(f"\nLabel column: {label_column}")
        print("\nLabel distribution in the sample:")
        print(sample[label_column].astype(str).value_counts().head(20))
    else:
        print("\nNo obvious label column found in the sample.")


def main() -> None:
    if not DATA_DIR.exists():
        raise FileNotFoundError(f"Dataset folder not found: {DATA_DIR.resolve()}")

    csv_files = sorted(DATA_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR.resolve()}")

    print(f"Dataset directory: {DATA_DIR.resolve()}")
    print(f"CSV files found: {len(csv_files)}")

    for file_path in csv_files:
        try:
            inspect_dataset(file_path)
        except Exception as error:
            print(f"\nCould not inspect {file_path.name}: {error}")


if __name__ == "__main__":
    main()