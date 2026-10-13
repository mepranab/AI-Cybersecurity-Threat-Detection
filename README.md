# Sentinel AI — AI-Powered Cybersecurity Threat Detection

Sentinel AI is a student-built cybersecurity research prototype
that uses machine learning to analyse network-flow data and
identify potentially suspicious traffic.

The project uses the CICIDS2017 dataset and a Streamlit dashboard
to demonstrate a network-threat detection workflow.

## Project Objectives

- Analyse network-flow data.
- Apply machine-learning models to network traffic.
- Compare classification performance.
- Display potential threats in a dashboard.
- Support alert review and investigation.
- Demonstrate a reproducible cybersecurity research workflow.

## Technology Stack

- Python
- Pandas and NumPy
- Scikit-learn
- Logistic Regression
- Random Forest
- Streamlit
- Plotly
- Joblib
- Pytest

## Dataset

This project uses the CICIDS2017 intrusion-detection dataset.

The original dataset is not included in this repository because
of its size. Obtain the dataset from its official source and place
the compatible CSV files in `data/raw/`.

## Project Structure

```text
AI-Cybersecurity-Threat-Detection/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── data/
│   ├── raw/
│   ├── processed/
│   └── sample/
├── scripts/
│   ├── inspect_real_dataset.py
│   └── train_real_models.py
├── src/
├── models/
├── outputs/
│   └── metrics/
├── tests/
├── docs/
└── images/