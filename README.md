# 🛡️ Sentinel AI — AI-Powered Cybersecurity Threat Detection System

<p align="center">
  <strong>Machine Learning • Network Security • Threat Analytics • Security Operations</strong>
</p>

<p align="center">
  A student-built cybersecurity research prototype that applies machine learning
  to network traffic analysis and presents potential threats through an interactive
  Security Operations Centre dashboard.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Machine%20Learning-scikit--learn-orange" alt="Machine Learning">
  <img src="https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?logo=streamlit" alt="Streamlit">
  <img src="https://img.shields.io/badge/Dataset-CICIDS2017-blue" alt="CICIDS2017">
  <img src="https://img.shields.io/badge/Project-Academic%20Prototype-purple" alt="Academic Prototype">
</p>

---

## 📌 Table of Contents

- [Project Overview](#-project-overview)
- [Problem Statement](#-problem-statement)
- [Industry Relevance](#-industry-relevance)
- [Project Objectives](#-project-objectives)
- [Key Features](#-key-features)
- [Technology Stack](#-technology-stack)
- [System Architecture](#-system-architecture)
- [Dataset Details](#-dataset-details)
- [Machine Learning Approach](#-machine-learning-approach)
- [Model Evaluation](#-model-evaluation)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Running the Application](#-running-the-application)
- [Using the Dashboard](#-using-the-dashboard)
- [Screenshots](#-screenshots)
- [Results and Limitations](#-results-and-limitations)
- [Security and Responsible Use](#-security-and-responsible-use)
- [Learning Outcomes](#-learning-outcomes)
- [Future Enhancements](#-future-enhancements)
- [Author](#-author)

---

## 🚀 Project Overview

**Sentinel AI** is an AI-powered network threat detection and investigation
prototype designed to demonstrate how machine learning can support cybersecurity
monitoring.

The project uses network-flow features from the CICIDS2017 dataset to train
machine learning classifiers that distinguish between benign traffic and
potentially malicious traffic.

The trained model is integrated into a Streamlit dashboard that allows users
to upload network traffic CSV files, analyze multiple files in batches, review
predictions, examine model evaluation metrics, and explore cumulative detection
results.

The application is designed to demonstrate a simplified Security Operations
Centre (SOC) workflow, bringing machine learning, data analysis, and security
visualization together in one interface.

### Project at a Glance

| Component | Description |
|---|---|
| Project name | Sentinel AI |
| Project category | AI-powered cybersecurity |
| Primary objective | Network traffic classification and threat investigation |
| Dataset | CICIDS2017 |
| Machine learning | Logistic Regression and Random Forest |
| Interface | Streamlit web dashboard |
| Programming language | Python |
| Primary input | Network-flow CSV files |
| Primary output | Traffic predictions, potential-threat counts, and evaluation reports |
| Intended use | Academic demonstration and cybersecurity research |

---

## 🎯 Problem Statement

Modern networks generate large volumes of traffic, making manual inspection
and investigation time-consuming.

Security analysts need ways to prioritize suspicious activity, examine
network-flow characteristics, and identify traffic that deserves further
investigation.

Traditional rule-based monitoring can be useful, but machine learning offers
another approach: identifying patterns in network traffic based on previously
observed examples.

This project explores the following question:

> How can machine learning and an interactive dashboard be combined to classify
> network traffic and help users investigate potentially suspicious activity?

Sentinel AI addresses this question through a prototype workflow that combines:

1. Network traffic data ingestion.
2. Data preparation and feature alignment.
3. Supervised machine learning.
4. Batch-based prediction.
5. Cumulative result storage.
6. Interactive visualization and investigation.

The resulting predictions are intended to support analysis, not replace
professional security monitoring or incident-response decisions.

---

## 🏢 Industry Relevance

Sentinel AI demonstrates concepts relevant to several cybersecurity and
technology roles.

### Security Operations Centre (SOC)

SOC teams investigate alerts, prioritize suspicious activity, and examine
network behavior. The dashboard demonstrates how model predictions can be
presented in an investigation-oriented interface.

### Network Security Monitoring

Network-flow records contain information about communication patterns,
packet counts, durations, ports, and traffic characteristics.

Analyzing these features can help demonstrate how traffic classification
systems identify patterns associated with potential attacks.

### Security Data Analytics

Cybersecurity datasets can contain millions of records. Batch processing and
aggregated statistics help make large-scale analysis more manageable.

### Applied Machine Learning

The project connects model training and evaluation with an application that
can accept new CSV files and generate predictions.

### Relevant Job Roles

- Junior SOC Analyst
- Cybersecurity Analyst Intern
- Security Data Analyst
- Junior Python Developer
- Machine Learning Intern
- Security Automation Intern

This project is an educational demonstration of relevant concepts, not a
substitute for professional cybersecurity experience.

---

## 🎯 Project Objectives

The primary objectives are:

- Build a machine-learning-based network traffic classification prototype.
- Explore the CICIDS2017 intrusion-detection dataset.
- Train and evaluate Logistic Regression and Random Forest classifiers.
- Integrate a trained model into a web-based dashboard.
- Support batch processing of multiple network traffic CSV files.
- Preserve cumulative prediction results between application reruns.
- Visualize prediction distributions and selected network-flow characteristics.
- Present model evaluation metrics in an accessible format.
- Demonstrate responsible interpretation of automated security predictions.

---

## ✨ Key Features

### 1. Interactive Security Dashboard

The Streamlit application provides a centralized interface for reviewing
network traffic analysis and model-generated predictions.

### 2. Machine Learning-Based Classification

The application loads a previously trained model and uses network-flow
features to classify traffic.

Predictions are grouped into categories such as:

- `BENIGN`
- `POTENTIAL_ATTACK`

These labels are model outputs and should not be interpreted as definitive
proof of malicious activity.

### 3. Multi-File CSV Analysis

Users can select multiple compatible CSV files and analyze them through a
batch-processing workflow.

The application processes records in chunks to reduce memory pressure when
working with larger datasets.

### 4. Cumulative Prediction Storage

Processed predictions can be appended to a persistent CSV report:

`outputs/reports/cumulative_detection_results.csv`

This supports analysis across multiple files and application reruns.

The file records predictions generated by the application. It is not a
database of independently verified security incidents.

### 5. Threat Investigation

The investigation interface presents model-generated threat signals and
associated network-flow features for further examination.

### 6. Model Performance Dashboard

The application presents evaluation metrics such as:

- Accuracy
- Precision
- Recall
- F1-score
- False-positive rate

These metrics help demonstrate the strengths and limitations of the evaluated
classifiers.

### 7. Network Activity Visualization

The dashboard can display distributions and summaries derived from prediction
results, including destination-port activity and attack-score distributions
where supported by the available data.

### 8. Geographic Threat Map

The project includes a geographic visualization component.

Actual geographic mapping requires usable latitude/longitude coordinates or
compatible IP-address fields together with an appropriate geolocation source.

Standard CICIDS2017 flow files may not provide the required source IP
information. Consequently, geographic mapping is conditional on the available
data and configuration.

The system must not invent geographic locations when the required information
is unavailable.

---

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.11 | Primary programming language |
| Pandas | Data manipulation and CSV processing |
| NumPy | Numerical operations |
| Scikit-learn | Machine learning, preprocessing, and evaluation |
| Logistic Regression | Baseline classification model |
| Random Forest | Tree-based classification model |
| Streamlit | Interactive dashboard |
| Plotly | Interactive charts and visualizations |
| Matplotlib | Supporting data visualization |
| Seaborn | Statistical visualization |
| Joblib | Saving and loading trained model artifacts |
| Pytest | Automated testing framework |
| Git | Version control |
| GitHub | Source-code hosting and project portfolio |

Optional geographic visualization dependencies may include `geoip2` and a
compatible local GeoLite2 database.

---

## 🏗️ System Architecture

The application follows a simplified machine-learning inference pipeline.

```text
                 ┌────────────────────────┐
                 │   CICIDS2017 Dataset   │
                 └────────────┬───────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │ Data Inspection and    │
                 │ Feature Preparation    │
                 └────────────┬───────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │ Model Training         │
                 │ Logistic Regression    │
                 │ Random Forest          │
                 └────────────┬───────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │ Saved Model Artifacts  │
                 │ Joblib Files           │
                 └────────────┬───────────┘
                              │
                              ▼
┌──────────────────┐  ┌────────────────────────┐
│ Multiple Network │─▶│ CSV Ingestion and      │
│ Traffic CSVs     │  │ Batch Processing       │
└──────────────────┘  └────────────┬───────────┘
                                   │
                                   ▼
                      ┌────────────────────────┐
                      │ Feature Alignment and  │
                      │ Model Inference        │
                      └────────────┬───────────┘
                                   │
                                   ▼
                      ┌────────────────────────┐
                      │ Traffic Predictions    │
                      │ and Threat Signals     │
                      └────────────┬───────────┘
                                   │
                    ┌──────────────┴─────────────┐
                    ▼                            ▼
        ┌────────────────────┐       ┌────────────────────┐
        │ Cumulative CSV     │       │ Streamlit Dashboard│
        │ Prediction Reports │       │ Charts and Metrics │
        └────────────────────┘       └────────────────────┘
```

### Workflow Explanation

1. Inspect the dataset and identify usable network-flow features.
2. Prepare training data and train classification models.
3. Evaluate the trained models using held-out data.
4. Save model artifacts for subsequent inference.
5. Upload one or more compatible CSV files through the dashboard.
6. Process records in manageable batches.
7. Align input features with the model's expected feature columns.
8. Generate predictions for the processed records.
9. Append results to the cumulative prediction report.
10. Review aggregate statistics, visualizations, and potential threats.

---

## 📊 Dataset Details

### CICIDS2017

The project uses the **CICIDS2017 dataset**, developed by the Canadian
Institute for Cybersecurity.

The dataset contains network traffic and labeled examples designed to support
research into intrusion detection and network traffic classification.

Official dataset resource:

[Canadian Institute for Cybersecurity — Intrusion Detection Evaluation Dataset (CICIDS2017)](https://www.unb.ca/cic/datasets/ids-2017.html)

### Data Characteristics

Depending on the selected file, network-flow records can contain features such
as:

- Destination port
- Flow duration
- Forward and backward packet counts
- Forward and backward packet lengths
- Flow byte rate
- Flow packet rate
- Inter-arrival-time statistics
- Additional network-flow measurements
- Original traffic labels, when included

The exact columns depend on the source file and dataset version.

### Dataset Preparation

The training workflow uses bounded sampling from the available CSV files to
make experimentation more manageable on a local computer.

The prototype training process uses a binary classification target:

| Category | Meaning |
|---|---|
| `BENIGN` | Traffic labeled benign |
| `POTENTIAL_ATTACK` | Traffic labeled as an attack or non-benign according to the training workflow |

The binary target is a simplification of the dataset's original labels.
It does not preserve every attack category.

### Dataset Size and Hardware

The complete dataset contains substantial CSV files. The training workflow
samples records from individual files rather than necessarily loading every
record into memory simultaneously.

Inference uses batch processing to reduce memory usage.

**Important:** Results from a bounded sample should not be described as a
comprehensive evaluation of the complete CICIDS2017 dataset.

### Data Availability

The raw dataset is not included in this repository because of its size and
dataset redistribution considerations.

Obtain the data from the official dataset provider and place compatible CSV
files in:

```text
data/raw/
```

Do not upload large raw datasets to GitHub as part of the normal source-code
submission.

---

## 🤖 Machine Learning Approach

The project evaluates two supervised classification algorithms.

### 1. Logistic Regression

Logistic Regression serves as a baseline model for binary classification.

It estimates the probability of a sample belonging to a class based on the
input features.

**Purpose:** Establish a baseline for comparing model performance.

### 2. Random Forest

Random Forest combines predictions from multiple decision trees.

It can capture nonlinear relationships between network-flow features and
classification labels.

**Purpose:** Evaluate a tree-based alternative to the baseline model.

### Training Workflow

The prototype training script performs the following operations:

1. Reads the available dataset files.
2. Samples a bounded number of records per file.
3. prepares the binary target labels.
4. Separates input features from the target.
5. Creates a stratified training/test split.
6. Fits the classification models.
7. Calculates evaluation metrics.
8. Saves model artifacts and evaluation results.

### Model Artifacts

The project stores model-related files in:

```text
outputs/
└── metrics/
    ├── logistic_regression_prototype.joblib
    ├── random_forest_prototype.joblib
    └── prototype_model_metrics.json
```

The dashboard uses a saved model artifact for prediction. The precise artifact
selected by the application should be verified in `app.py`.

The training and inference workflows must use compatible feature columns,
preprocessing, and label definitions.

---

## 📈 Model Evaluation

The current dashboard displays the following prototype evaluation results.

| Metric | Logistic Regression | Random Forest |
|---|---:|---:|
| Accuracy | 95.94% | 100.00% |
| Precision | 27.51% | 100.00% |
| Recall | 96.82% | 99.68% |
| F1-score | 42.84% | 99.84% |
| False-positive rate | 4.08% | 0.00% |

These figures reflect the evaluation results currently displayed by the
project. They should be rechecked against the saved metrics file before being
used in a final report or presentation.

### Understanding the Metrics

**Accuracy**

The proportion of evaluated records classified correctly.

**Precision**

The proportion of records predicted as attacks that were actually attacks
according to the evaluation labels.

**Recall**

The proportion of attack-labeled records identified by the model.

**F1-score**

The harmonic mean of precision and recall.

**False-positive rate**

The proportion of benign records incorrectly classified as attacks.

### Important Evaluation Limitation

The displayed Random Forest results are unusually strong and require careful
interpretation.

Related or duplicate network flows may appear in both training and test
partitions when using a random row-level split. This can inflate apparent
performance and make results less representative of previously unseen
network activity.

The reported metrics therefore **do not establish production-level detection
accuracy**.

Further evaluation should include:

- Checking for duplicate and near-duplicate records across partitions.
- Testing on a separate capture period or appropriately separated dataset.
- Evaluating performance for individual attack categories.
- Reviewing precision-recall trade-offs.
- Testing against data from a different network environment.
- Measuring inference speed and memory consumption.
- Confirming that the evaluation and inference preprocessing pipelines match.

The project should be treated as a research prototype until these limitations
have been addressed.

---

## 📁 Project Structure

The principal project components are organized as follows:

```text
AI-Cybersecurity-Threat-Detection/
│
├── app.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── .streamlit/
│   └── config.toml
│
├── data/
│   ├── raw/
│   ├── processed/
│   ├── sample/
│   └── geolocation/
│
├── models/
│   └── sample_model.joblib
│
├── outputs/
│   ├── metrics/
│   │   ├── logistic_regression_prototype.joblib
│   │   ├── random_forest_prototype.joblib
│   │   └── prototype_model_metrics.json
│   │
│   ├── alerts/
│   └── reports/
│       └── cumulative_detection_results.csv
│
├── scripts/
│   ├── inspect_real_dataset.py
│   └── train_real_models.py
│
├── src/
├── tests/
└── images/
```

Some directories are created or populated when the application or training
scripts run. Their contents may not be present in a fresh repository clone.

Generated reports, large datasets, and private geolocation databases should
remain excluded from Git unless there is a specific reason to distribute them.

---

## ⚙️ Installation

### Prerequisites

Install the following:

- Python 3.11 or a compatible version.
- Git.
- Visual Studio Code or another Python editor.
- A compatible CICIDS2017 CSV file for testing.
- The project repository.

### Step 1: Clone the Repository

Replace the repository address below if your GitHub username or repository
name differs.

```bash
git clone https://github.com/mepranab/AI-Cybersecurity-Threat-Detection.git
```

Navigate into the project:

```bash
cd AI-Cybersecurity-Threat-Detection
```

### Step 2: Create a Virtual Environment

On Windows:

```powershell
python -m venv .venv
```

Activate it in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt:

```bat
.venv\Scripts\activate.bat
```

### Step 3: Install Dependencies

Upgrade pip:

```powershell
python -m pip install --upgrade pip
```

Install the project dependencies:

```powershell
python -m pip install -r requirements.txt
```

The requirements file should contain the dependencies actually used by the
application and training scripts.

If the project uses a separate optional geolocation feature, install its
dependency when required:

```powershell
python -m pip install geoip2
```

### Step 4: Verify the Installation

Run:

```powershell
python -c "import pandas, numpy, sklearn, streamlit, joblib, plotly; print('Core dependencies installed successfully')"
```

If the command prints the success message, the main dependencies are available.

### Step 5: Check Required Model Files

Confirm that the model artifact selected by `app.py` exists.

The trained model files are located in:

```text
outputs/metrics/
```

If the application expects a file that is missing from the repository, train
the model locally using the provided training script, provided the required
dataset is available.

---

## ▶️ Running the Application

Activate the virtual environment and navigate to the project root.

Start the Streamlit application:

```powershell
python -m streamlit run app.py
```

Streamlit will display a local address in the terminal, usually:

```text
http://localhost:8501
```

Open the displayed address in your browser.

If port 8501 is already in use, Streamlit may select another port. Use the
address printed in the terminal.

To stop the server, return to the terminal and press:

```text
Ctrl + C
```

---

## 🔍 Using the Dashboard

### Step 1: Open the Application

Launch `app.py` with Streamlit and open the local dashboard.

### Step 2: Review the Executive Overview

Review the available summary metrics, prediction counts, and dashboard status.

Metrics should be interpreted according to whether they describe training,
evaluation, the current analysis, or previously saved results.

### Step 3: Upload Network Traffic CSV Files

Navigate to the Threat Detection page.

Select one or more compatible network traffic CSV files using the upload
control.

For large datasets, allow the application to process the files in batches.
Avoid uploading unnecessarily large files when working on a memory-limited
computer.

### Step 4: Run the Analysis

Start the analysis using the dashboard's detection button.

The application uses the configured model to generate predictions for
compatible input features.

### Step 5: Review Predictions

Inspect the resulting traffic classifications and potential-threat counts.

A potential-attack prediction is a signal for further analysis, not confirmation
that an incident has occurred.

### Step 6: Review Cumulative Results

When cumulative processing is used, results are saved to:

```text
outputs/reports/cumulative_detection_results.csv
```

The dashboard may provide an option to download the cumulative prediction
report.

Check the output file after processing to verify that the expected records
have been saved.

### Step 7: Investigate Network Activity

Use the investigation and visualization pages to examine the available
network-flow fields and model-generated signals.

Geographic mapping depends on compatible IP or coordinate data. If the input
does not contain the required information, the application should report that
limitation rather than inventing geographic results.

---

## 🖼️ Screenshots

Screenshots help recruiters understand the project without having to run it.

Save screenshots of the working dashboard in the `images/` directory.

Recommended screenshots:

### 1. Executive Overview

Show the main dashboard, summary metrics, and system status.

![Sentinel AI Executive Overview](images/executive_overview.png)

### 2. Threat Detection

Show the multi-file upload interface, batch analysis controls, and processing
results.

![Sentinel AI Threat Detection](images/threat_detection.png)

### 3. Model Evaluation

Show the model comparison table and evaluation charts.

![Sentinel AI Model Evaluation](images/model_evaluation.png)

### 4. Alert Investigation

Show the investigation table and available filters.

![Sentinel AI Alert Investigation](images/alert_investigation.png)

### 5. Threat Map

Show the geographic visualization when valid geographic data is available.

![Sentinel AI Threat Map](images/threat_map.png)

**Before publishing:** Add the corresponding image files to `images/`, or
replace these paths with the actual screenshot filenames. Remove any image
entry for which you do not have a screenshot.

Do not present an unavailable geographic map as a successfully working feature.

---

## 📊 Results and Limitations

### Results

The current prototype demonstrates:

- Training and saving two machine learning classifiers.
- Generating predictions from compatible network-flow CSV files.
- Processing multiple CSV files through a batch workflow.
- Saving cumulative prediction results to a CSV report.
- Presenting model evaluation metrics in a dashboard.
- Visualizing selected network traffic characteristics.
- Exploring an investigation-oriented cybersecurity interface.

### Limitations

The current implementation has several important limitations:

1. **Prototype evaluation:** Random train/test splits can overestimate
   performance when related flows appear in both partitions.

2. **Dataset dependence:** Predictions are only meaningful when input features
   are compatible with the trained model.

3. **Binary classification:** The simplified target does not provide complete
   identification of every attack category.

4. **Geographic coverage:** A threat map requires suitable coordinates or
   usable IP-address information and a compatible geolocation source.

5. **No confirmed incidents:** Model predictions are not equivalent to
   independently verified attacks.

6. **Operational security:** The application has not been established as a
   production-grade intrusion detection or incident-response platform.

7. **Generalization:** Performance on one research dataset does not guarantee
   equivalent performance on live enterprise networks.

These limitations provide opportunities for future development and evaluation.

---

## 🔐 Security and Responsible Use

Sentinel AI is intended for educational use, research, and demonstration.

Users should:

- Analyze network traffic they are authorized to access.
- Avoid uploading sensitive production traffic to an untrusted environment.
- Keep credentials, API keys, and private configuration files out of Git.
- Exclude private geolocation databases from public repositories.
- Treat model predictions as investigation signals.
- Validate results before making security decisions.
- Follow applicable dataset licensing and attribution requirements.
- Avoid claiming that an IP-derived geographic location identifies a specific
  attacker or physical device.

This prototype does not replace a professional SOC, an established intrusion
detection system, or a validated incident-response process.

---

## 🎓 Learning Outcomes

This project demonstrates practical experience with several technical areas.

### Python Development

- Organizing a Python project into logical components.
- Managing dependencies and virtual environments.
- Handling files and structured datasets.
- Working with saved model artifacts.

### Data Science

- Inspecting and preparing CSV datasets.
- Selecting model input features.
- Handling binary classification labels.
- Sampling large datasets for experimentation.
- Calculating and interpreting evaluation metrics.

### Machine Learning

- Training Logistic Regression and Random Forest classifiers.
- Comparing model performance.
- Applying trained models to new data.
- Understanding precision, recall, F1-score, and false-positive rates.
- Recognizing evaluation leakage and generalization risks.

### Cybersecurity

- Understanding network-flow analysis.
- Exploring intrusion-detection datasets.
- Examining potential threat classifications.
- Presenting model outputs in an investigation-oriented workflow.
- Recognizing the difference between an alert and a confirmed incident.

### Application Development

- Building interactive applications with Streamlit.
- Creating charts and tables for analytical results.
- Processing CSV files in batches.
- Persisting prediction results.
- Organizing a dashboard into functional pages.

### Software Engineering

- Using Git for version control.
- Hosting a project on GitHub.
- Managing project dependencies.
- Structuring files and generated outputs.
- Documenting installation, operation, and limitations.

---

## 🚧 Future Enhancements

Potential improvements include:

- Evaluation using temporally or independently separated datasets.
- More detailed classification of individual attack categories.
- Improved model calibration and decision-threshold selection.
- Automated tests for data preprocessing and prediction.
- Stronger validation of uploaded CSV schemas.
- Improved logging and error reporting.
- More efficient persistent storage for large prediction histories.
- Better handling of duplicate files and repeated analysis.
- Geographic visualization when valid location data is available.
- Explainability tools for investigating model predictions.
- Authentication and access controls for deployment.
- Containerized deployment and automated testing through CI/CD.
- Integration with approved security monitoring tools.

These are potential extensions and should not be interpreted as features that
are already implemented.

---

## 👨‍💻 Author

**Ripunjoy Das**

Student Developer | Cybersecurity and Machine Learning Enthusiast

GitHub: [@mepranab](https://github.com/mepranab)

### Project

**Sentinel AI — AI-Powered Cybersecurity Threat Detection System**

This project was developed as an academic and portfolio-oriented exploration
of machine learning, network traffic analysis, and interactive cybersecurity
visualization.

---

## 📄 Disclaimer

Sentinel AI is an educational research prototype. Its output is not a
guarantee of attack detection, and its evaluation results do not establish
production readiness.

All potential threats require appropriate investigation and validation.

---