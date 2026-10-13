from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from io import BytesIO
from pathlib import Path
from urllib.parse import quote

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

# ---------------------------- Configuration ----------------------------
ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "outputs/metrics/random_forest_prototype.joblib"
METRICS_PATH = ROOT / "outputs/metrics/prototype_model_metrics.json"
REPORT_DIR = ROOT / "outputs/reports"
ALERT_DIR = ROOT / "outputs/alerts"
GEO_DIR = ROOT / "data/geolocation"
RESULTS_PATH = REPORT_DIR / "cumulative_detection_results.csv"
ALERTS_PATH = ALERT_DIR / "cumulative_alerts.csv"
SUMMARY_PATH = REPORT_DIR / "detection_summary.json"
BATCH_SIZE = 5000
PREVIEW_LIMIT = 20000
ATTACK_LABELS = {"POTENTIAL_ATTACK", "ATTACK", "MALICIOUS", "1", "TRUE"}

st.set_page_config(page_title="Sentinel AI | Security Operations", page_icon="🛡️", layout="wide")

# ------------------------------- Styling ------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
.stApp {background:radial-gradient(ellipse at 75% 0%,#172b49 0%,#0b1120 48%,#070c16 100%);color:#e5edf8}
[data-testid="stHeader"]{background:rgba(7,12,22,.9)}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#101a2b,#080e19);border-right:1px solid #263a55}
[data-testid="stMetric"]{background:linear-gradient(145deg,rgba(20,37,61,.98),rgba(11,22,39,.98));border:1px solid #2a4260;padding:16px;border-radius:15px}
[data-testid="stMetricLabel"]{color:#9db1cc}
[data-testid="stMetricValue"]{color:#f4f8ff;font-weight:800}
h1,h2,h3{letter-spacing:-.025em;color:#f5f8ff}
.hero{font-size:34px;font-weight:800;letter-spacing:-1.2px;color:#f8fbff}
.subhero{color:#91a8c6;margin-top:2px;margin-bottom:16px}
div.stButton>button[kind="primary"]{background:linear-gradient(90deg,#0284c7,#2563eb);border:0;border-radius:10px;font-weight:700}
div.stButton>button{border-radius:9px}
div[data-testid="stDataFrame"]{border:1px solid #263a55;border-radius:12px;overflow:hidden}
[data-testid="stPlotlyChart"]{border:1px solid rgba(51,65,85,.7);border-radius:14px;padding:6px;background:rgba(10,17,31,.35)}
</style>
""", unsafe_allow_html=True)


def ensure_dirs():
    for path in (REPORT_DIR, ALERT_DIR):
        path.mkdir(parents=True, exist_ok=True)

    if GEO_DIR.exists() and not GEO_DIR.is_dir():
        raise RuntimeError(
            f"'{GEO_DIR}' exists as a file. "
            "Rename or move that file, then create a folder named geolocation."
        )

    GEO_DIR.mkdir(parents=True, exist_ok=True)


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        return {}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")
    temp.replace(path)


def load_metrics():
    return read_json(METRICS_PATH) or None


def label_text(value):
    return str(value).strip().upper()


def is_attack(value):
    return label_text(value) in ATTACK_LABELS


def load_summary():
    meta = read_json(SUMMARY_PATH)
    if meta:
        return meta
    # Recover row count if an old result CSV exists but its summary file is missing.
    if RESULTS_PATH.exists():
        try:
            with RESULTS_PATH.open("r", encoding="utf-8", errors="ignore") as f:
                rows = max(0, sum(1 for _ in f) - 1)
            return {"total_rows": rows, "attack_count": 0, "files_processed": [], "last_run": None}
        except OSError:
            pass
    return {"total_rows": 0, "attack_count": 0, "files_processed": [], "last_run": None}


def load_preview():
    if not RESULTS_PATH.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(RESULTS_PATH, nrows=PREVIEW_LIMIT, low_memory=True)
    except Exception:
        return pd.DataFrame()


def chart_style(fig, height=390):
    fig.update_layout(
        template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(13,24,42,.45)",
        font=dict(family="Inter, Segoe UI, sans-serif", color="#d4e0f0", size=12),
        height=height, margin=dict(l=20, r=20, t=65, b=25),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        title=dict(x=.02, xanchor="left", font=dict(size=17, color="#f8fafc")),
    )
    fig.update_xaxes(showgrid=False, linecolor="#263a55")
    fig.update_yaxes(gridcolor="rgba(148,163,184,.14)", zerolinecolor="#334155")
    return fig


def make_alerts(df):
    if df.empty or "Prediction" not in df.columns:
        return pd.DataFrame()
    out = df[df["Prediction"].map(is_attack)].copy()
    if out.empty:
        return out
    if "Attack Score" in out.columns:
        scores = pd.to_numeric(out["Attack Score"], errors="coerce").fillna(0)
        out["Risk Score"] = (scores * 100).round(1)
        out["Severity"] = np.select(
            [scores >= .90, scores >= .75, scores >= .50],
            ["Critical", "High", "Medium"], default="Low"
        )
    else:
        out["Risk Score"] = np.nan
        out["Severity"] = "Review"
    out["Detection Source"] = "Random Forest prototype"
    out["Investigation Note"] = "Model-generated signal; analyst review required."
    return out


def attack_probabilities(model, X):
    """Find the model's attack-class probability without assuming class order."""
    if not hasattr(model, "predict_proba"):
        return None
    try:
        probs = model.predict_proba(X)
        classes = [label_text(c) for c in getattr(model, "classes_", [])]
        idx = next((i for i, c in enumerate(classes) if c in ATTACK_LABELS), None)
        if idx is None and len(classes) == 2:
            benign_idx = next((i for i, c in enumerate(classes) if c in {"BENIGN", "NORMAL", "0", "FALSE"}), None)
            if benign_idx is not None:
                idx = 1 - benign_idx
        return probs[:, idx] if idx is not None else None
    except Exception:
        return None


def find_column(df, candidates):
    norm = {str(c).strip().lower().replace("_", " ").replace("-", " "): c for c in df.columns}
    for item in candidates:
        key = item.lower().replace("_", " ").replace("-", " ")
        if key in norm:
            return norm[key]
    return None


def make_geo_points(df):
    """Prefer actual coordinate columns; otherwise try a local GeoLite2 City database."""
    if df.empty:
        return pd.DataFrame(), "No saved prediction sample exists yet."
    lat_col = find_column(df, ["latitude", "lat", "source latitude", "src latitude", "source lat", "src lat"])
    lon_col = find_column(df, ["longitude", "lon", "lng", "source longitude", "src longitude", "source lon", "src lon"])
    if lat_col and lon_col:
        pts = df.copy()
        pts["Latitude"] = pd.to_numeric(pts[lat_col], errors="coerce")
        pts["Longitude"] = pd.to_numeric(pts[lon_col], errors="coerce")
        pts = pts.dropna(subset=["Latitude", "Longitude"])
        pts = pts[pts["Latitude"].between(-90, 90) & pts["Longitude"].between(-180, 180)]
        if not pts.empty:
            pts["Geo source"] = "Coordinates supplied in CSV"
            return pts, None

    ip_col = find_column(df, ["Source IP", "Source IP Address", "src_ip", "src ip", "Source Address"])
    if not ip_col:
        return pd.DataFrame(), "No coordinate columns or recognizable source IP column were found."
    db_path = GEO_DIR / "GeoLite2-City.mmdb"
    if not db_path.exists():
        return pd.DataFrame(), (
            f"Source IPs were found in '{ip_col}', but GeoLite2 is not installed. "
            f"If you obtain the database, put it at {db_path.relative_to(ROOT)}."
        )
    try:
        import geoip2.database
    except ImportError:
        return pd.DataFrame(), "Install the optional lookup library: python -m pip install geoip2"

    points = []
    try:
        with geoip2.database.Reader(str(db_path)) as reader:
            for _, row in df.head(5000).iterrows():
                raw = str(row.get(ip_col, "")).strip()
                try:
                    ip = ipaddress.ip_address(raw)
                    if not ip.is_global:
                        continue
                    city = reader.city(raw)
                    lat, lon = city.location.latitude, city.location.longitude
                    if lat is None or lon is None:
                        continue
                    points.append({
                        "IP": raw, "Latitude": lat, "Longitude": lon,
                        "Prediction": row.get("Prediction", "Unknown"),
                        "Attack Score": row.get("Attack Score", np.nan),
                        "Geo source": "GeoLite2 approximate IP geolocation",
                    })
                except Exception:
                    continue
    except Exception as exc:
        return pd.DataFrame(), f"Could not read GeoLite2 database: {exc}"
    if not points:
        return pd.DataFrame(), "No public IPs in the saved sample returned usable GeoLite2 coordinates."
    return pd.DataFrame(points), None


def process_files(uploaded_files):
    if not MODEL_PATH.exists():
        st.error(f"Model file not found: {MODEL_PATH.relative_to(ROOT)}")
        return
    try:
        artifact = joblib.load(MODEL_PATH)
    except Exception as exc:
        st.error(f"Could not load model artifact: {exc}")
        return
    if not isinstance(artifact, dict) or "model" not in artifact or "feature_columns" not in artifact:
        st.error("Model artifact must contain 'model' and 'feature_columns'.")
        return

    model = artifact["model"]
    feature_columns = list(artifact["feature_columns"])
    meta = load_summary()
    rows_added = 0
    attacks_added = 0
    files_done = []
    progress = st.progress(0)
    status = st.empty()

    for file_idx, uploaded in enumerate(uploaded_files):
        file_rows = 0
        file_attacks = 0
        first_write = not RESULTS_PATH.exists()
        try:
            reader = pd.read_csv(BytesIO(uploaded.getvalue()), chunksize=BATCH_SIZE, low_memory=True)
            for chunk in reader:
                chunk.columns = chunk.columns.astype(str).str.strip()
                excluded = {"label", "class", "attack", "target"}
                features = chunk.drop(columns=[c for c in chunk.columns if c.lower().strip() in excluded], errors="ignore")
                missing = [col for col in feature_columns if col not in features.columns]
                if missing:
                    st.error(
                        f"'{uploaded.name}' is missing {len(missing)} required feature columns. "
                        f"Examples: {missing[:12]}. This CSV is not compatible with the selected model."
                    )
                    return
                X = features[feature_columns].copy()
                for col in feature_columns:
                    X[col] = pd.to_numeric(X[col], errors="coerce")
                X = X.replace([np.inf, -np.inf], np.nan)
                predictions = model.predict(X)
                result = chunk.copy()
                result["Prediction"] = predictions
                scores = attack_probabilities(model, X)
                if scores is not None:
                    result["Attack Score"] = np.asarray(scores, dtype=float)
                mask = result["Prediction"].map(is_attack)
                n = len(result)
                attack_n = int(mask.sum())
                file_rows += n
                file_attacks += attack_n
                rows_added += n
                attacks_added += attack_n

                # Durable append: every processed row is written, not just the UI preview.
                result.to_csv(RESULTS_PATH, mode="a", header=first_write, index=False)
                first_write = False

                alert_rows = make_alerts(result)
                if not alert_rows.empty:
                    alert_header = not ALERTS_PATH.exists()
                    alert_rows.to_csv(ALERTS_PATH, mode="a", header=alert_header, index=False)

                status.write(f"Processing {file_idx + 1}/{len(uploaded_files)}: {uploaded.name} — {file_rows:,} rows.")
        except pd.errors.EmptyDataError:
            st.warning(f"{uploaded.name} is empty and was skipped.")
            continue
        except Exception as exc:
            st.error(f"Failed while processing {uploaded.name}: {exc}")
            st.exception(exc)
            return

        files_done.append({
            "name": uploaded.name, "rows": file_rows,
            "potential_attacks": file_attacks,
            "processed_at": datetime.now().isoformat(timespec="seconds"),
        })
        progress.progress(int((file_idx + 1) / max(1, len(uploaded_files)) * 100))

    if rows_added == 0:
        st.warning("No rows were processed.")
        return
    meta.setdefault("files_processed", [])
    meta["files_processed"].extend(files_done)
    meta["total_rows"] = int(meta.get("total_rows", 0)) + rows_added
    meta["attack_count"] = int(meta.get("attack_count", 0)) + attacks_added
    meta["last_run"] = datetime.now().isoformat(timespec="seconds")
    meta["last_run_rows"] = rows_added
    meta["last_run_attacks"] = attacks_added
    write_json(SUMMARY_PATH, meta)
    st.session_state["summary"] = meta
    st.session_state["preview"] = load_preview()
    st.session_state["last_files"] = [f["name"] for f in files_done]
    status.success(f"Finished: {rows_added:,} new rows from {len(files_done)} file(s); {attacks_added:,} potential-attack predictions.")
    st.rerun()


# ------------------------------ Startup state ------------------------------
ensure_dirs()
if "summary" not in st.session_state:
    st.session_state["summary"] = load_summary()
if "preview" not in st.session_state:
    st.session_state["preview"] = load_preview()
summary = st.session_state["summary"]
preview = st.session_state["preview"]
metrics = load_metrics()

# --------------------------------- Sidebar ----------------------------------
with st.sidebar:
    st.markdown("## 🛡️ SENTINEL AI")
    st.caption("Network Threat Detection & Investigation")
    st.divider()
    page = st.radio(
        "NAVIGATION",
        ["Executive Overview", "Threat Detection", "Threat Map", "Alert Investigation",
         "Model Performance", "Threat Intelligence", "System Health"],
        key="sentinel_navigation",
    )
    st.divider()
    st.caption("PROJECT STATUS")
    st.write(f"{'🟢' if MODEL_PATH.exists() else '🔴'} Random Forest model {'available' if MODEL_PATH.exists() else 'missing'}")
    st.write(f"{'🟢' if METRICS_PATH.exists() else '🟡'} Evaluation metrics {'available' if METRICS_PATH.exists() else 'not found'}")
    st.write(f"{'🟢' if RESULTS_PATH.exists() else '⚪'} Cumulative results {'saved' if RESULTS_PATH.exists() else 'not run'}")
    st.caption("Student research prototype • investigate before acting")

st.markdown('<div class="hero">Security Operations Centre</div>', unsafe_allow_html=True)
st.markdown('<div class="subhero">AI-powered network analytics • cumulative detection • investigation workspace</div>', unsafe_allow_html=True)
h1, h2 = st.columns([3, 1])
with h1:
    st.info("Research prototype: model predictions are investigation signals, not proof of an attack. IP geolocation is approximate.")
with h2:
    st.markdown(f"**Local time**  \n{datetime.now().strftime('%d %b %Y, %H:%M:%S')}")
st.divider()

# ---------------------------- Executive Overview ----------------------------
if page == "Executive Overview":
    st.subheader("Security Overview")
    total = int(summary.get("total_rows", 0))
    attacks = int(summary.get("attack_count", 0))
    recall = None
    if metrics:
        model_data = metrics.get("models", {})
        selected = next((v for k, v in model_data.items() if "random" in k.lower()), None)
        if selected is None and model_data:
            selected = next(iter(model_data.values()))
        recall = selected.get("recall") if selected else None
    a, b, c, d = st.columns(4)
    a.metric("Cumulative flows analysed", f"{total:,}")
    b.metric("Potential-attack predictions", f"{attacks:,}")
    c.metric("Potential alerts", f"{attacks:,}")
    d.metric("Offline evaluation recall", f"{recall:.3f}" if isinstance(recall, (int, float)) else "—")
    if total == 0:
        st.info("Open Threat Detection to upload one or more compatible CSVs. Predictions will be saved on disk and accumulate across runs.")
    else:
        left, right = st.columns(2)
        with left:
            distribution = pd.DataFrame({"Prediction": ["Potential attack", "Benign / other"], "Flows": [attacks, max(0, total - attacks)]})
            fig = px.pie(distribution, names="Prediction", values="Flows", hole=.60, title="Cumulative prediction distribution")
            st.plotly_chart(chart_style(fig), use_container_width=True)
        with right:
            file_history = summary.get("files_processed", [])
            if file_history:
                hist = pd.DataFrame(file_history[-10:]).iloc[::-1]
                fig = px.bar(hist, x="name", y="rows", color="potential_attacks", title="Rows processed by recent file", hover_data=["processed_at"])
                fig.update_xaxes(tickangle=-25, title="File")
                st.plotly_chart(chart_style(fig), use_container_width=True)
            else:
                st.info("File-level history is not available.")
        st.markdown("### Recent saved prediction sample")
        if not preview.empty:
            st.dataframe(preview.head(100), use_container_width=True, height=300)
        st.caption(f"Full history: `{RESULTS_PATH.relative_to(ROOT)}`. UI preview is limited to {PREVIEW_LIMIT:,} rows.")
    if st.button("Refresh saved history"):
        st.session_state["summary"] = load_summary()
        st.session_state["preview"] = load_preview()
        st.rerun()

# ------------------------------ Threat Detection ----------------------------
elif page == "Threat Detection":
    st.subheader("Batch Network Threat Detection")
    st.write("Select multiple CSV files. Each file is processed in 5,000-row chunks; all predictions are appended to persistent cumulative files.")
    if not MODEL_PATH.exists():
        st.error(f"Model file missing: `{MODEL_PATH.relative_to(ROOT)}`")
    else:
        uploads = st.file_uploader(
            "Upload one or more network-flow CSV files", type=["csv"],
            accept_multiple_files=True, key="sentinel_multi_upload",
            help="Use compatible CICIDS2017 feature columns. Avoid selecting the same file twice unless you want it counted twice.",
        )
        x, y, z = st.columns(3)
        x.metric("Previously saved rows", f"{int(summary.get('total_rows', 0)):,}")
        y.metric("Previously saved potential attacks", f"{int(summary.get('attack_count', 0)):,}")
        z.metric("Selected files", f"{len(uploads) if uploads else 0:,}")
        left, right = st.columns([2, 1])
        with left:
            run = st.button("▶ Run cumulative analysis", type="primary", disabled=not uploads)
        with right:
            reset = st.button("Reset cumulative history", help="Deletes saved prediction, alert, and summary files.")
        if reset:
            for path in (RESULTS_PATH, ALERTS_PATH, SUMMARY_PATH):
                try:
                    path.unlink(missing_ok=True)
                except OSError as exc:
                    st.error(f"Could not delete {path.name}: {exc}")
            st.session_state["summary"] = load_summary()
            st.session_state["preview"] = pd.DataFrame()
            st.success("Saved cumulative history cleared.")
            st.rerun()
        if run and uploads:
            process_files(uploads)
        st.divider()
        st.markdown("### Cumulative output files")
        if RESULTS_PATH.exists():
            st.success(f"Prediction history saved to `{RESULTS_PATH.relative_to(ROOT)}`")
            st.download_button("Download full cumulative predictions", data=RESULTS_PATH.read_bytes(),
                               file_name="sentinel_ai_cumulative_predictions.csv", mime="text/csv")
        else:
            st.info("No results saved yet.")

# -------------------------------- Threat Map -------------------------------
elif page == "Threat Map":
    st.subheader("Geographic Threat Map")
    st.caption(
        "Displays supplied coordinates or approximate public-IP locations "
        "from a local GeoLite2 database."
    )

    points, message = make_geo_points(preview)

    if not points.empty:
        if len(points) > 5000:
            points = points.sample(5000, random_state=42)
            st.caption("Showing up to 5,000 points for browser performance.")

        color = "Prediction" if "Prediction" in points.columns else "Geo source"
        hover = [
            col for col in ["IP", "Prediction", "Attack Score", "Geo source"]
            if col in points.columns
        ]

        fig_map = px.scatter_geo(
            points,
            lat="Latitude",
            lon="Longitude",
            color=color,
            hover_name="IP" if "IP" in points.columns else None,
            hover_data=hover,
            projection="natural earth",
            title="Mapped network-flow locations",
            template="plotly_dark",
        )
        fig_map.update_geos(
            showland=True,
            landcolor="#172438",
            showocean=True,
            oceancolor="#081426",
            showcountries=True,
            countrycolor="#334155",
            showcoastlines=True,
            coastlinecolor="#475569",
        )
        st.plotly_chart(
            chart_style(fig_map, 560),
            use_container_width=True,
            config={"displayModeBar": True, "responsive": True},
        )

        metric_a, metric_b = st.columns(2)
        metric_a.metric("Mapped points", f"{len(points):,}")
        attack_points = (
            int(points["Prediction"].map(is_attack).sum())
            if "Prediction" in points.columns else 0
        )
        metric_b.metric("Potential-attack points", f"{attack_points:,}")
        st.dataframe(points.head(100), use_container_width=True)
        st.warning(
            "IP geolocation is approximate and does not establish an attacker's "
            "exact physical location."
        )
    else:
        st.warning(
            message
            or "Geographic coordinates are unavailable. Showing network threat activity instead."
        )

    st.markdown("### Network Threat Activity")
    st.caption(
        "These charts use your actual model predictions. "
        "They show network activity, not geographic attacker locations."
    )

    if RESULTS_PATH.exists():
        try:
            threat_data = pd.read_csv(
                RESULTS_PATH,
                low_memory=True,
                nrows=100000,
            )

            if threat_data.empty:
                st.info("The cumulative prediction file contains no records.")
            else:
                if "Attack Score" in threat_data.columns:
                    threat_data["Attack Score"] = pd.to_numeric(
                        threat_data["Attack Score"], errors="coerce"
                    )

                # Chart 1: destination ports, with flow count on X and port on Y.
                if "Destination Port" in threat_data.columns:
                    port_data = threat_data.copy()
                    port_data["Destination Port"] = pd.to_numeric(
                        port_data["Destination Port"], errors="coerce"
                    )
                    port_data = port_data.dropna(subset=["Destination Port"])

                    if not port_data.empty:
                        port_summary = (
                            port_data.groupby("Destination Port")
                            .size()
                            .reset_index(name="Flow Count")
                            .nlargest(15, "Flow Count")
                            .sort_values("Flow Count", ascending=True)
                        )

                        fig_ports = px.bar(
                            port_summary,
                            x="Flow Count",
                            y="Destination Port",
                            orientation="h",
                            title="Top 15 Destination Ports by Flow Count",
                            template="plotly_dark",
                            color="Flow Count",
                            color_continuous_scale="Blues",
                        )
                        fig_ports.update_layout(
                            height=500,
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(13,24,42,.45)",
                            font=dict(
                                family="Inter, Segoe UI, sans-serif",
                                color="#d4e0f0",
                                size=12,
                            ),
                            title=dict(
                                x=0.02,
                                xanchor="left",
                                font=dict(size=17, color="#f8fafc"),
                            ),
                            xaxis_title="Number of network flows",
                            yaxis_title="Destination port",
                            coloraxis_showscale=False,
                            margin=dict(l=30, r=25, t=65, b=45),
                            showlegend=False,
                        )
                        fig_ports.update_yaxes(
                            type="category",
                            gridcolor="rgba(148,163,184,.14)",
                            automargin=True,
                        )
                        fig_ports.update_xaxes(
                            rangemode="tozero",
                            showgrid=True,
                            gridcolor="rgba(148,163,184,.14)",
                        )
                        st.plotly_chart(
                            fig_ports,
                            use_container_width=True,
                            config={"displayModeBar": True, "responsive": True},
                        )
                    else:
                        st.info("No usable destination-port values were found.")
                else:
                    st.info("Destination Port is unavailable in the saved results.")

                # Chart 2: cumulative model prediction distribution.
                if "Prediction" in threat_data.columns:
                    prediction_summary = (
                        threat_data["Prediction"]
                        .fillna("Unknown")
                        .astype(str)
                        .value_counts()
                        .rename_axis("Prediction")
                        .reset_index(name="Flow Count")
                    )

                    fig_predictions = px.pie(
                        prediction_summary,
                        names="Prediction",
                        values="Flow Count",
                        hole=0.58,
                        title="Cumulative Model Prediction Distribution",
                        template="plotly_dark",
                        color_discrete_sequence=["#6366F1", "#F97316", "#22C55E", "#38BDF8"],
                    )
                    fig_predictions.update_traces(
                        textposition="inside",
                        textinfo="percent",
                        insidetextfont=dict(color="#ffffff", size=12),
                        hovertemplate="%{label}<br>Flow count: %{value:,}<br>Share: %{percent}<extra></extra>",
                    )
                    fig_predictions.update_layout(
                        height=450,
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(13,24,42,.45)",
                        font=dict(
                            family="Inter, Segoe UI, sans-serif",
                            color="#d4e0f0",
                            size=12,
                        ),
                        title=dict(
                            x=0.02,
                            xanchor="left",
                            font=dict(size=17, color="#f8fafc"),
                        ),
                        legend=dict(
                            orientation="h",
                            yanchor="bottom",
                            y=1.02,
                            xanchor="left",
                            x=0,
                        ),
                        margin=dict(l=25, r=25, t=90, b=35),
                    )
                    st.plotly_chart(
                        fig_predictions,
                        use_container_width=True,
                        config={"displayModeBar": True, "responsive": True},
                    )

                # Chart 3: distribution of model attack scores.
                if "Attack Score" in threat_data.columns:
                    scores = threat_data["Attack Score"].dropna()
                    if not scores.empty:
                        score_frame = pd.DataFrame({"Attack Score": scores})
                        fig_scores = px.histogram(
                            score_frame,
                            x="Attack Score",
                            nbins=30,
                            title="Distribution of Model Attack Scores",
                            template="plotly_dark",
                            color_discrete_sequence=["#38BDF8"],
                        )
                        fig_scores.update_layout(
                            height=400,
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(13,24,42,.45)",
                            font=dict(
                                family="Inter, Segoe UI, sans-serif",
                                color="#d4e0f0",
                                size=12,
                            ),
                            title=dict(
                                x=0.02,
                                xanchor="left",
                                font=dict(size=17, color="#f8fafc"),
                            ),
                            xaxis_title="Model attack score",
                            yaxis_title="Number of network flows",
                            margin=dict(l=35, r=25, t=65, b=45),
                        )
                        fig_scores.update_xaxes(
                            range=[0, 1],
                            gridcolor="rgba(148,163,184,.14)",
                        )
                        fig_scores.update_yaxes(
                            rangemode="tozero",
                            gridcolor="rgba(148,163,184,.14)",
                        )
                        st.plotly_chart(
                            fig_scores,
                            use_container_width=True,
                            config={"displayModeBar": True, "responsive": True},
                        )

                st.caption(
                    "These visualizations summarize saved prediction records. "
                    "A high model score is an investigation signal, not proof "
                    "of a confirmed attack."
                )
        except Exception as exc:
            st.error(f"Could not load cumulative threat activity: {exc}")
    else:
        st.info(
            "Run an analysis from Threat Detection to create cumulative results."
        )

# --------------------------- Alert Investigation ----------------------------
elif page == "Alert Investigation":
    st.subheader("Alert Investigation")
    if not ALERTS_PATH.exists():
        st.info("No potential-attack alerts have been saved yet.")
    else:
        try:
            alerts = pd.read_csv(ALERTS_PATH, nrows=5000, low_memory=True)
        except Exception as exc:
            alerts = pd.DataFrame()
            st.error(f"Could not read alerts: {exc}")
        if alerts.empty:
            st.success("No saved potential-attack predictions were found.")
        else:
            st.caption("Alerts are model-generated signals, not confirmed incidents.")
            if "Severity" in alerts:
                levels = sorted(alerts["Severity"].dropna().unique().tolist())
                chosen = st.multiselect("Filter severity", levels, default=levels)
                alerts = alerts[alerts["Severity"].isin(chosen)]
            st.dataframe(alerts.head(1000), use_container_width=True, height=400)
            st.download_button("Download cumulative alerts", data=ALERTS_PATH.read_bytes(),
                               file_name="sentinel_ai_cumulative_alerts.csv", mime="text/csv")

# ----------------------------- Model Performance ----------------------------
elif page == "Model Performance":
    st.subheader("Model Evaluation")
    if not metrics:
        st.warning(f"Metrics file missing or invalid: `{METRICS_PATH.relative_to(ROOT)}`")
    else:
        st.caption(f"Experiment: {metrics.get('experiment', 'Prototype experiment')}")
        st.warning("Offline evaluation only. Random splits can overestimate performance when related flows appear in both training and test data.")
        model_results = metrics.get("models", {})
        if not model_results:
            st.warning("No model metrics found under 'models'.")
        else:
            rows = []
            for name, values in model_results.items():
                rows.append({"Model": name.replace("_", " ").title(),
                             "Accuracy": values.get("accuracy"), "Precision": values.get("precision"),
                             "Recall": values.get("recall"), "F1-score": values.get("f1_score"),
                             "False-positive rate": values.get("false_positive_rate")})
            comparison = pd.DataFrame(rows)
            st.dataframe(comparison, use_container_width=True, hide_index=True)
            melted = comparison.melt(id_vars="Model", value_vars=["Precision", "Recall", "F1-score"],
                                     var_name="Metric", value_name="Score").dropna()
            if not melted.empty:
                fig = px.bar(melted, x="Model", y="Score", color="Metric", barmode="group",
                             title="Precision, recall and F1-score", range_y=[0, 1])
                st.plotly_chart(chart_style(fig), use_container_width=True)
            for name, values in model_results.items():
                cm = values.get("confusion_matrix")
                if isinstance(cm, dict) and cm.get("values") and cm.get("labels"):
                    matrix = pd.DataFrame(cm["values"], index=cm["labels"], columns=cm["labels"])
                    fig = px.imshow(matrix, text_auto=True, aspect="auto",
                                    title=f"{name.replace('_', ' ').title()} confusion matrix",
                                    labels={"x": "Predicted", "y": "Actual", "color": "Flows"})
                    st.plotly_chart(chart_style(fig, 360), use_container_width=True)

# ---------------------------- Threat Intelligence ---------------------------
elif page == "Threat Intelligence":
    st.subheader("Threat Intelligence Quick Lookup")
    st.write("Create external investigation links for an IP. The dashboard does not automatically query these services.")
    ip_col = find_column(preview, ["Source IP", "Source IP Address", "src_ip", "src ip", "Source Address"]) if not preview.empty else None
    if ip_col:
        options = preview[ip_col].dropna().astype(str).str.strip()
        options = options[options.ne("")].drop_duplicates().head(100).tolist()
        ip_value = st.selectbox("Select a source IP from saved results", options) if options else st.text_input("Enter IP")
    else:
        ip_value = st.text_input("Enter an IP address")
    if ip_value:
        try:
            parsed = ipaddress.ip_address(ip_value.strip())
            if not parsed.is_global:
                st.warning("This IP is private, reserved, or non-global; public services may have no useful information.")
            safe_ip = quote(str(parsed), safe="")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**VirusTotal**  \n[Open IP report](https://www.virustotal.com/gui/ip-address/{safe_ip})")
                st.markdown(f"**AbuseIPDB**  \n[Check IP reputation](https://www.abuseipdb.com/check/{safe_ip})")
            with c2:
                st.markdown(f"**GreyNoise**  \n[Open IP lookup](https://viz.greynoise.io/ip/{safe_ip})")
                st.markdown(f"**IPinfo**  \n[Open IP details](https://ipinfo.io/{safe_ip})")
            st.caption("External services may require sign-in or show no record. Do not send sensitive internal IPs to third parties without authorization.")
        except ValueError:
            st.error("Enter a valid IPv4 or IPv6 address.")

# -------------------------------- System Health -----------------------------
elif page == "System Health":
    st.subheader("System Health")
    checks = [
        ("Dashboard", True, "Streamlit page is rendering"),
        ("Random Forest model", MODEL_PATH.exists(), str(MODEL_PATH.relative_to(ROOT))),
        ("Evaluation metrics", METRICS_PATH.exists(), str(METRICS_PATH.relative_to(ROOT))),
        ("Cumulative predictions", RESULTS_PATH.exists(), str(RESULTS_PATH.relative_to(ROOT))),
        ("Cumulative summary", SUMMARY_PATH.exists(), str(SUMMARY_PATH.relative_to(ROOT))),
        ("GeoLite2 database (optional)", (GEO_DIR / "GeoLite2-City.mmdb").exists(), str((GEO_DIR / "GeoLite2-City.mmdb").relative_to(ROOT))),
    ]
    for name, ok, detail in checks:
        (st.success if ok else st.warning)(f"**{name}:** {'Available' if ok else 'Not available'} — `{detail}`")
    st.markdown("### Cumulative summary")
    st.json(summary)
    st.markdown("### Persistent output locations")
    st.code(f"Predictions: {RESULTS_PATH.relative_to(ROOT)}\nAlerts: {ALERTS_PATH.relative_to(ROOT)}\nSummary: {SUMMARY_PATH.relative_to(ROOT)}")

st.divider()
st.caption("Sentinel AI • Student cybersecurity research prototype • Investigate model signals before taking action.")
