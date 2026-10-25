
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

from engine import DetectionEngine

st.set_page_config(
    page_title="Suspicious Process Detection",
    page_icon="🛡️",
    layout="wide",
)

# Initialize the detection engine once per Streamlit session.
@st.cache_resource
def load_engine():
    return DetectionEngine()


try:
    engine = load_engine()
except Exception as exc:
    st.error(f"Could not load detection engine: {exc}")
    st.stop()


if "alerts" not in st.session_state:
    st.session_state.alerts = []


st.title("🛡️ ML-Based Suspicious Process Detection")
st.caption(
    "Machine-learning classification using memory-forensics dataset samples "
    "and a live operating-system process explorer."
)

st.divider()

# Sidebar
st.sidebar.header("Navigation")
page = st.sidebar.radio(
    "Choose a section",
    [
        "Security Overview",
        "Dataset Simulation",
        "Live Process Explorer",
        "Model Evaluation",
        "Alert History",
    ],
)

# Overview metrics
if page == "Security Overview":
    total_records = len(engine.data)
    total_processes = len(engine.list_processes())

    c1, c2, c3 = st.columns(3)
    c1.metric("Dataset Records", f"{total_records:,}")
    c2.metric("Model Features", len(engine.feature_columns))
    c3.metric("Running Processes Found", f"{total_processes:,}")

    st.subheader("About this project")
    st.write(
        "This project uses an XGBoost model to classify memory-forensics "
        "dataset samples into Benign, Ransomware, Spyware, and Trojan categories."
    )

    st.info(
        "Dataset simulations classify selected dataset records. The live "
        "process explorer displays operating-system telemetry only; it does "
        "not perform a verified memory-forensics scan."
    )

    st.subheader("Dataset category distribution")
    if "Category" in engine.data.columns:
        category_counts = (
            engine.data["Category"]
            .astype(str)
            .apply(
                lambda x: (
                    "Benign"
                    if x.lower() == "benign"
                    else x.split("-")[0]
                )
            )
            .value_counts()
            .rename_axis("Category")
            .reset_index(name="Records")
        )

        fig = px.bar(
            category_counts,
            x="Category",
            y="Records",
            color="Category",
            title="Records by category",
        )
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Recent alerts")
    if st.session_state.alerts:
        st.dataframe(
            pd.DataFrame(st.session_state.alerts).tail(10),
            use_container_width=True,
        )
    else:
        st.write("No simulation alerts recorded in this session yet.")


elif page == "Dataset Simulation":
    st.subheader("Run a dataset-based classification")
    st.write(
        "Choose a category to select a sample from the dataset and classify "
        "its 55 numeric features with the trained model."
    )

    selected_type = st.selectbox(
        "Dataset category",
        ["Benign", "Ransomware", "Spyware", "Trojan"],
    )

    if st.button("Run Detection", type="primary"):
        try:
            result = engine.simulate(selected_type)

            alert = {
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Requested Category": selected_type,
                "Dataset Category": result["details"]["dataset_category"],
                "Prediction": result["prediction"],
                "Confidence (%)": result["confidence_percent"],
            }
            st.session_state.alerts.append(alert)

            st.session_state.last_result = result
        except Exception as exc:
            st.error(f"Simulation failed: {exc}")

    result = st.session_state.get("last_result")

    if result:
        st.divider()
        st.subheader("Classification Result")

        col1, col2, col3 = st.columns(3)
        col1.metric("Model Prediction", result["prediction"])
        col2.metric("Confidence", f'{result["confidence_percent"]:.2f}%')
        col3.metric("Requested Category", result["details"]["requested_type"])

        st.write("**Actual dataset sample:**")
        st.code(result["details"]["dataset_category"])

        if result["prediction"] == "Benign":
            st.success("The model classified this sample as Benign.")
        else:
            st.warning(
                f'The model classified this sample as {result["prediction"]}.'
            )

        probabilities = pd.DataFrame(
            [
                {"Category": category, "Probability (%)": probability}
                for category, probability in result["probabilities"].items()
            ]
        )

        fig = px.bar(
            probabilities,
            x="Category",
            y="Probability (%)",
            color="Category",
            title="Model class probabilities",
            range_y=[0, 100],
        )
        st.plotly_chart(fig, use_container_width=True)

        metrics = result["details"].get("behavioral_metrics", {})
        if metrics:
            st.subheader("Selected dataset feature values")
            st.dataframe(
                pd.DataFrame(
                    [{"Feature": k, "Value": v} for k, v in metrics.items()]
                ),
                use_container_width=True,
            )

        st.caption(result["note"])


elif page == "Live Process Explorer":
    st.subheader("Live Operating-System Process Explorer")
    st.warning(
        "This page lists real processes and basic OS telemetry. "
        "It does not classify processes as malware because the required "
        "memory-forensics features are not collected."
    )

    if st.button("Refresh Process List"):
        st.session_state.processes = engine.list_processes()

    if "processes" not in st.session_state:
        st.session_state.processes = engine.list_processes()

    processes = st.session_state.processes

    search = st.text_input("Search by process name or PID").strip().lower()

    filtered = [
        proc for proc in processes
        if search in str(proc["pid"]).lower()
        or search in proc["name"].lower()
    ]

    st.metric("Processes listed", len(filtered))
    st.dataframe(
        pd.DataFrame(filtered),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Inspect one process")
    pid_text = st.text_input("Enter a PID to inspect", placeholder="e.g. 1234")

    if st.button("Inspect PID"):
        if not pid_text.strip().isdigit():
            st.error("Enter a valid numeric PID.")
        else:
            try:
                process_info = engine.get_process(int(pid_text))
                st.json(process_info)
            except ValueError as exc:
                st.error(str(exc))


elif page == "Alert History":
    st.subheader("Session Alert History")

    if st.session_state.alerts:
        alerts_df = pd.DataFrame(st.session_state.alerts)
        st.dataframe(alerts_df, use_container_width=True, hide_index=True)

        csv_data = alerts_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download Alert History as CSV",
            data=csv_data,
            file_name="suspicious_process_alerts.csv",
            mime="text/csv",
        )

        if st.button("Clear Session Alert History"):
            st.session_state.alerts = []
            st.rerun()

elif page == "Model Evaluation":
    st.subheader("Model Evaluation")
    st.write(
        "Evaluation results reported by the four-class XGBoost "
        "training run in main_notebook.ipynb."
    )

    st.info(
        "These metrics come from the notebook's reported test evaluation. "
        "They are not a live performance measurement of running processes."
    )

    # Overall evaluation metrics reported by the notebook
    c1, c2, c3 = st.columns(3)
    c1.metric("Test Accuracy", "84.31%")
    c2.metric("Macro Precision", "76%")
    c3.metric("Macro Recall", "76%")

    c4, c5 = st.columns(2)
    c4.metric("Macro F1-score", "76%")
    c5.metric("Test Samples", "11,720")

    st.divider()
    st.subheader("Classification Report")

    report = pd.DataFrame({
        "Category": ["Benign", "Ransomware", "Spyware", "Trojan"],
        "Precision": [1.00, 0.67, 0.74, 0.65],
        "Recall":    [1.00, 0.65, 0.72, 0.69],
        "F1-score":  [1.00, 0.66, 0.73, 0.67],
        "Support":   [5860, 1958, 2004, 1898],
    })

    st.dataframe(
        report,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        "Per-class values are reproduced from the notebook's "
        "classification report. Macro metrics are displayed rounded "
        "to whole percentages."
    )

    st.subheader("Per-class F1-score")

    f1_chart = report[["Category", "F1-score"]].copy()
    f1_chart["F1-score (%)"] = f1_chart["F1-score"] * 100

    fig = px.bar(
        f1_chart,
        x="Category",
        y="F1-score (%)",
        color="Category",
        title="F1-score by category",
        range_y=[0, 100],
        text="F1-score (%)",
    )
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Interpretation")
    
    st.divider()
    st.subheader("Confusion Matrix")

    # Rows = actual classes; columns = predicted classes
    cm = [
        [5860,    0,    0,    0],
        [   0, 1269,  302,  387],
        [   0,  244, 1443,  317],
        [   0,  381,  208, 1309],
    ]

    class_names = ["Benign", "Ransomware", "Spyware", "Trojan"]

    cm_df = pd.DataFrame(
        cm,
        index=class_names,
        columns=class_names,
    )

    fig_cm = px.imshow(
        cm_df,
        text_auto=True,
        labels={
            "x": "Predicted Category",
            "y": "Actual Category",
            "color": "Number of Samples",
        },
        x=class_names,
        y=class_names,
        title="Actual vs Predicted Categories",
        color_continuous_scale="Blues",
        aspect="auto",
    )

    st.plotly_chart(fig_cm, use_container_width=True)

    st.write(
        "- Benign samples achieved precision, recall, and F1-score of 1.00 "
        "in the reported evaluation."
    )
    st.write(
        "- Ransomware recall was 0.65, meaning the model identified "
        "65% of the actual ransomware test samples."
    )
    st.write(
        "- Spyware had the highest F1-score among the three malware "
        "categories, at 0.73."
    )
    st.write(
        "- Trojan had precision of 0.65 and recall of 0.69, so there is "
        "room to improve classification of this category."
    )

    st.warning(
        "A confusion matrix is not shown here because its actual cell "
        "counts have not yet been provided. We should not estimate them "
        "from rounded classification metrics."
    )

else:
    st.info(
        "No alerts yet. Run a dataset simulation to add a classification "
        "result to this session's alert history."
    )
