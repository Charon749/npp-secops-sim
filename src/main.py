from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter

from src.agents.alert_judgement_agent import AlertJudgementAgent
from src.agents.early_warning_agent import EarlyWarningAgent
from src.data_generator import generate_sample_data
from src.evaluation.metrics import compute_metrics
from src.models import AlertRecord
from src.reporting.report_generator import generate_outputs
from src.workflow.workflow_engine import WorkflowEngine


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "outputs"


def load_alerts(path: Path) -> list[AlertRecord]:
    with path.open("r", encoding="utf-8") as handle:
        return [AlertRecord.from_dict(json.loads(line)) for line in handle if line.strip()]


def run_simulation() -> dict[str, object]:
    sample_path = DATA_DIR / "sample_alerts.jsonl"
    if not sample_path.exists():
        generate_sample_data(DATA_DIR)
    alerts = load_alerts(sample_path)
    alert_by_id = {alert.alert_id: alert for alert in alerts}

    judgement_agent = AlertJudgementAgent()
    workflow_engine = WorkflowEngine()
    judgements = []
    workflows = []

    for alert in alerts:
        related_alerts = [
            alert_by_id[related_id]
            for related_id in alert.related_alert_ids
            if related_id in alert_by_id
        ]
        started = perf_counter()
        judgement = judgement_agent.judge_alert(alert, related_alerts=related_alerts)
        judgement.judgement_time_ms = round((perf_counter() - started) * 1000, 4)
        workflow = workflow_engine.process(judgement)
        judgements.append(judgement)
        workflows.append(workflow)

    incidents = EarlyWarningAgent().aggregate(alerts)
    metrics = compute_metrics(alerts, judgements, workflows)
    results_path, report_path = generate_outputs(alerts, judgements, workflows, metrics, incidents, OUTPUT_DIR)
    return {
        "alerts": alerts,
        "judgements": judgements,
        "workflows": workflows,
        "incidents": incidents,
        "metrics": metrics,
        "results_path": results_path,
        "report_path": report_path,
    }


def main() -> None:
    result = run_simulation()
    metrics = result["metrics"]
    print("Simulation completed.")
    print(f"Total alerts: {int(metrics['total_alerts'])}")
    print(f"Risk consistency: {metrics['risk_level_consistency_rate']:.4f}")
    print(f"Workflow accuracy: {metrics['workflow_trigger_accuracy']:.4f}")
    print(f"Results CSV: {result['results_path']}")
    print(f"Evaluation report: {result['report_path']}")


if __name__ == "__main__":
    main()
