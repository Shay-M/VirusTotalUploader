"""VirusTotal File Scanner (GUI)

This tool keeps the existing VirusTotal logic (hashing, report checking, uploading,
analysis polling) but presents it in a simple customtkinter UI.

Usage:
    python vt_uploader.py "C:\path\to\file.ext"

The GUI will start immediately and begin scanning the provided file.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import requests

import customtkinter as ctk

# Optional dotenv support (not required if env var is already set)
try:
    from dotenv import load_dotenv  # type: ignore

    _HAS_DOTENV = True
except ImportError:  # pragma: no cover
    _HAS_DOTENV = False


VT_API_KEY_ENV = "VT_API_KEY"
VT_API_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class AnalysisSummary:
    sha256: str
    total_engines: int
    malicious: int
    suspicious: int
    report_url: str
    last_scan_date: str = ""


def load_api_key() -> str:
    """Load VirusTotal API key from env var or optional .env file."""

    if _HAS_DOTENV:
        load_dotenv(dotenv_path=".env")

    api_key = os.getenv(VT_API_KEY_ENV)
    if not api_key:
        raise RuntimeError(
            f"VirusTotal API key not found. Set {VT_API_KEY_ENV} in your environment or in a .env file."
        )
    return api_key.strip()


def sha256_of_file(path: Path, chunk_size: int = 16 * 1024) -> str:
    """Compute SHA-256 hash for a file in streaming fashion."""

    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def vt_headers(api_key: str) -> Dict[str, str]:
    return {"x-apikey": api_key}


def get_file_report(api_key: str, file_hash: str) -> Optional[Dict[str, Any]]:
    """Query VirusTotal for an existing file report by hash."""

    url = f"{VT_API_BASE}/files/{file_hash}"
    resp = requests.get(url, headers=vt_headers(api_key), timeout=60)

    if resp.status_code == 200:
        return resp.json()

    if resp.status_code == 404:
        return None

    resp.raise_for_status()
    return None


def poll_analysis(api_key: str, analysis_id: str, poll_interval: int = 15, max_attempts: int = 80) -> Dict[str, Any]:
    """Poll until the analysis status is completed."""

    url = f"{VT_API_BASE}/analyses/{analysis_id}"

    for attempt in range(1, max_attempts + 1):
        resp = requests.get(url, headers=vt_headers(api_key), timeout=60)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attributes = data.get("attributes", {})
        status = attributes.get("status")

        if status == "completed":
            return data

        if status is None:
            raise RuntimeError("Unexpected response structure from VirusTotal analysis endpoint.")

        time.sleep(poll_interval)

    raise TimeoutError(
        f"Analysis did not complete within {poll_interval * max_attempts} seconds (max attempts: {max_attempts})."
    )


def reanalyse_file(api_key: str, file_hash: str) -> Dict[str, Any]:
    """Trigger re-analysis for an existing file on VirusTotal."""

    url = f"{VT_API_BASE}/files/{file_hash}/analyse"
    resp = requests.post(url, headers=vt_headers(api_key), timeout=60)
    resp.raise_for_status()
    return resp.json().get("data", {})
    """Upload a file to VirusTotal and return the analysis response data."""

    size = file_path.stat().st_size

    if size <= 32 * 1024 * 1024:
        url = f"{VT_API_BASE}/files"
        with file_path.open("rb") as f:
            files = {"file": (file_path.name, f)}
            resp = requests.post(url, headers=vt_headers(api_key), files=files, timeout=300)

    else:
        url = f"{VT_API_BASE}/files/upload_url"
        resp = requests.get(url, headers=vt_headers(api_key), timeout=60)
        resp.raise_for_status()
        upload_url = resp.json().get("data")

        if not upload_url or not isinstance(upload_url, str):
            raise RuntimeError("Failed to retrieve upload URL from VirusTotal.")

        with file_path.open("rb") as f:
            files = {"file": (file_path.name, f)}
            resp = requests.post(upload_url, headers=vt_headers(api_key), files=files, timeout=300)

    resp.raise_for_status()
    return resp.json().get("data", {})


def summarize_report(data: Dict[str, Any]) -> AnalysisSummary:
    """Extract a clean summary from VirusTotal report data."""

    attributes = data.get("attributes", {})
    stats = attributes.get("stats", {})
    sha256 = attributes.get("sha256") or attributes.get("md5") or ""
    report_url = f"https://www.virustotal.com/gui/file/{sha256}/detection" if sha256 else ""

    last_scan_date = ""
    if "last_analysis_date" in attributes:
        timestamp = attributes["last_analysis_date"]
        dt = datetime.fromtimestamp(timestamp)
        last_scan_date = dt.strftime("%d/%m/%Y %H:%M")

    return AnalysisSummary(
        sha256=sha256,
        total_engines=sum(stats.values()) if isinstance(stats, dict) else 0,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        report_url=report_url,
        last_scan_date=last_scan_date,
    )


class VirusTotalScannerApp(ctk.CTk):
    def __init__(self, file_path: Path) -> None:
        super().__init__()
        self.title("VirusTotal File Scanner")
        self.geometry("600x400")
        self.resizable(False, False)

        self.file_path = file_path
        self.api_key = ""
        self.summary: Optional[AnalysisSummary] = None
        self.force_upload = False

        self._build_ui()
        self.after(100, self._start_scan)

    def _build_ui(self) -> None:
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.container = ctk.CTkFrame(self, corner_radius=12)
        self.container.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(self.container, text="Starting...", font=ctk.CTkFont(size=16, weight="bold"))
        self.status_label.grid(row=0, column=0, pady=(20, 10), padx=20, sticky="n")

        self.spinner = ctk.CTkProgressBar(self.container, mode="indeterminate")
        self.spinner.grid(row=1, column=0, padx=40, pady=(0, 20), sticky="ew")

        self.result_frame = ctk.CTkFrame(self.container, corner_radius=12)
        self.result_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.result_frame.grid_columnconfigure(0, weight=1)

        self.file_label = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=14, weight="bold"))
        self.sha_label = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=12))
        self.ratio_label = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=12))
        self.status_text = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=12))
        self.last_scan_label = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=12))

        self.buttons_frame = ctk.CTkFrame(self.container, corner_radius=12)
        self.buttons_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))
        self.buttons_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.scan_again_btn = ctk.CTkButton(
            self.buttons_frame, text="Scan Again / Force Re-upload", command=self._on_scan_again, state="disabled"
        )
        self.view_report_btn = ctk.CTkButton(
            self.buttons_frame, text="View Full Report", command=self._on_view_report, state="disabled"
        )
        self.close_btn = ctk.CTkButton(self.buttons_frame, text="Close", command=self.destroy)

        self.scan_again_btn.grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        self.view_report_btn.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        self.close_btn.grid(row=0, column=2, padx=8, pady=8, sticky="ew")

    def _start_scan(self) -> None:
        self._set_status("Loading API key...")
        self.spinner.start()
        self._run_in_thread(self._scan_worker)

    def _set_status(self, text: str) -> None:
        self.status_label.configure(text=text)

    def _run_in_thread(self, target: Any, *args: Any, **kwargs: Any) -> None:
        thread = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True)
        thread.start()

    def _scan_worker(self) -> None:
        try:
            self.api_key = load_api_key()
            self._update_status("Calculating hash...")
            file_hash = sha256_of_file(self.file_path)

            self._update_status("Checking VirusTotal for an existing report...")
            report = get_file_report(self.api_key, file_hash)

            if report is not None and not self.force_upload:
                data = report.get("data", {})
                summary = summarize_report(data)
                self._update_ui_with_summary(summary, "Existing report")
                return

            if self.force_upload and report is not None:
                self._update_status("Re-analysing existing file...")
                reanalyse_data = reanalyse_file(self.api_key, file_hash)
                analysis_id = reanalyse_data.get("id")
                if not analysis_id:
                    raise RuntimeError("Could not determine analysis ID after reanalyse.")
                self._update_status("Polling analysis status...")
                analysis_data = poll_analysis(self.api_key, analysis_id)
                summary = summarize_report(analysis_data)
                self._update_ui_with_summary(summary, "Re-analysis")
                return

            self._update_status("Uploading file to VirusTotal...")
            upload_data = upload_file(self.api_key, self.file_path)
            analysis_id = upload_data.get("id") or upload_data.get("analysis_id")

            if not analysis_id:
                raise RuntimeError("Could not determine analysis ID after upload.")

            self._update_status("Polling analysis status...")
            analysis_data = poll_analysis(self.api_key, analysis_id)
            summary = summarize_report(analysis_data)
            self._update_ui_with_summary(summary, "New analysis")

        except Exception as exc:
            self._update_status(f"Error: {exc}")
            print(traceback.format_exc(), file=sys.stderr)
            self.spinner.stop()

    def _update_status(self, text: str) -> None:
        self.after(0, lambda: self._set_status(text))

    def _update_ui_with_summary(self, summary: AnalysisSummary, context: str) -> None:
        def _update() -> None:
            self.spinner.stop()
            self.spinner.grid_remove()  # Hide the progress bar completely

            # Allow result_frame to expand into the space
            self.container.grid_rowconfigure(2, weight=1)

            self.status_label.configure(text=f"{context} - {summary.malicious} / {summary.total_engines} detections")

            bg_color = "#1f5f1f" if summary.malicious == 0 else "#7f1f1f"
            self.result_frame.configure(fg_color=bg_color)

            self.file_label.configure(text=f"File: {self.file_path.name}")
            self.sha_label.configure(text=f"SHA-256: {summary.sha256[:12]}...")
            self.ratio_label.configure(text=f"Detection: {summary.malicious}/{summary.total_engines}")
            self.status_text.configure(text=("Clean" if summary.malicious == 0 else "Malicious"))
            self.last_scan_label.configure(text=f"Last Scan: {summary.last_scan_date}")

            self.file_label.grid(row=0, column=0, sticky="w", pady=(12, 4), padx=12)
            self.sha_label.grid(row=1, column=0, sticky="w", pady=4, padx=12)
            self.ratio_label.grid(row=2, column=0, sticky="w", pady=4, padx=12)
            self.status_text.grid(row=3, column=0, sticky="w", pady=4, padx=12)
            self.last_scan_label.grid(row=4, column=0, sticky="w", pady=(4, 12), padx=12)

            self.scan_again_btn.configure(state="normal")
            self.view_report_btn.configure(state="normal")
            self.summary = summary
            self.force_upload = False

        self.after(0, _update)

    def _on_scan_again(self) -> None:
        self.force_upload = True
        self.scan_again_btn.configure(state="disabled")
        self.view_report_btn.configure(state="disabled")
        self._set_status("Re-scanning (force upload)...")
        self.spinner.start()
        self._run_in_thread(self._scan_worker)

    def _on_view_report(self) -> None:
        if not self.summary:
            return
        webbrowser.open(self.summary.report_url)


def main() -> int:
    parser = argparse.ArgumentParser(description="VirusTotal File Scanner (GUI)")
    parser.add_argument("file", help="Path to the file to scan")
    args = parser.parse_args()

    file_path = Path(args.file).expanduser().resolve()
    if not file_path.exists() or not file_path.is_file():
        print(f"ERROR: File not found: {file_path}")
        return 1

    app = VirusTotalScannerApp(file_path)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
