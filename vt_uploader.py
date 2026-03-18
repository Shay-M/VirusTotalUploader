import argparse
import hashlib
import os
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import customtkinter as ctk
import requests

try:
    from dotenv import load_dotenv
    _HAS_DOTENV = True
except ImportError:
    _HAS_DOTENV = False


VT_API_KEY_ENV = "VT_API_KEY"
VT_API_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class AnalysisSummary:
    """Stores a cleaned-up version of the VirusTotal analysis report."""
    sha256: str
    total_engines: int
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    report_url: str
    last_scan_date: str = ""
    relative_time: str = ""


def load_api_key() -> str:
    """Retrieves the API key from environment variables or .env file."""
    if _HAS_DOTENV:
        load_dotenv(dotenv_path=".env")

    api_key = os.getenv(VT_API_KEY_ENV)
    if not api_key:
        raise RuntimeError(f"VirusTotal API key not found. Please set {VT_API_KEY_ENV}.")
    return api_key.strip()


def sha256_of_file(path: Path, chunk_size: int = 64 * 1024) -> str:
    """Generates a SHA-256 hash of a file efficiently using chunks."""
    hasher = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def vt_headers(api_key: str) -> Dict[str, str]:
    """Returns standardized headers for VirusTotal API requests."""
    return {"x-apikey": api_key}


def format_relative_time(dt: datetime) -> str:
    """Formats a friendly relative time string."""
    diff = datetime.now() - dt

    if diff.days > 0:
        if diff.days == 1:
            return "(1 day ago)"
        return f"({diff.days} days ago)"

    hours = diff.seconds // 3600
    if hours > 0:
        if hours == 1:
            return "(1 hour ago)"
        return f"({hours} hours ago)"

    minutes = diff.seconds // 60
    if minutes > 0:
        if minutes == 1:
            return "(1 minute ago)"
        return f"({minutes} minutes ago)"

    return "(Just now)"


def summarize_report(data: Dict[str, Any]) -> AnalysisSummary:
    """Parses raw VirusTotal file JSON data into a clean AnalysisSummary object."""
    attributes = data.get("attributes", {})

    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}

    sha256 = attributes.get("sha256") or data.get("id") or ""
    report_url = f"https://www.virustotal.com/gui/file/{sha256}/detection" if sha256 else ""

    last_scan_str = ""
    relative_time = ""

    last_analysis_date = attributes.get("last_analysis_date")
    if last_analysis_date:
        scan_datetime = datetime.fromtimestamp(last_analysis_date)
        last_scan_str = scan_datetime.strftime("%d/%m/%Y %H:%M")
        relative_time = format_relative_time(scan_datetime)

    total_engines = sum(stats.values()) if isinstance(stats, dict) else 0

    return AnalysisSummary(
        sha256=sha256,
        total_engines=total_engines,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        report_url=report_url,
        last_scan_date=last_scan_str,
        relative_time=relative_time,
    )


def get_file_report(api_key: str, file_hash: str) -> Optional[Dict[str, Any]]:
    """Gets a file report from VirusTotal by file hash."""
    url = f"{VT_API_BASE}/files/{file_hash}"
    response = requests.get(url, headers=vt_headers(api_key), timeout=60)

    if response.status_code == 200:
        return response.json()
    if response.status_code == 404:
        return None

    response.raise_for_status()
    return None


def upload_file(api_key: str, file_path: Path) -> Dict[str, Any]:
    """Uploads a file, supporting large files via a generated upload URL if needed."""
    size = file_path.stat().st_size
    max_size_allowed = 650 * 1024 * 1024

    if size > max_size_allowed:
        raise RuntimeError(
            f"File size {size / (1024 ** 2):.1f}MB exceeds VirusTotal's limit of 650MB. "
            "Please use a smaller file."
        )

    if size <= 32 * 1024 * 1024:
        url = f"{VT_API_BASE}/files"
        with file_path.open("rb") as file_obj:
            files = {"file": (file_path.name, file_obj)}
            response = requests.post(url, headers=vt_headers(api_key), files=files, timeout=300)
    else:
        upload_url_response = requests.get(
            f"{VT_API_BASE}/files/upload_url",
            headers=vt_headers(api_key),
            timeout=60,
        )
        upload_url_response.raise_for_status()
        upload_url = upload_url_response.json().get("data")

        if not upload_url:
            raise RuntimeError("VirusTotal did not return an upload URL for the large file.")

        with file_path.open("rb") as file_obj:
            files = {"file": (file_path.name, file_obj)}
            response = requests.post(upload_url, headers=vt_headers(api_key), files=files, timeout=1800)

    response.raise_for_status()
    return response.json().get("data", {})


def reanalyse_file(api_key: str, file_hash: str) -> Dict[str, Any]:
    """Requests a new analysis for an existing file hash."""
    url = f"{VT_API_BASE}/files/{file_hash}/analyse"
    response = requests.post(url, headers=vt_headers(api_key), timeout=60)
    response.raise_for_status()
    return response.json().get("data", {})


def poll_analysis(api_key: str, analysis_id: str, file_hash: str) -> Dict[str, Any]:
    """Polls the analysis status until completion, then fetches the final file report."""
    url = f"{VT_API_BASE}/analyses/{analysis_id}"
    max_wait_seconds = 1200
    elapsed = 0
    poll_interval = 15

    while elapsed < max_wait_seconds:
        response = requests.get(url, headers=vt_headers(api_key), timeout=60)
        response.raise_for_status()

        analysis_data = response.json().get("data", {})
        status = analysis_data.get("attributes", {}).get("status")

        if status == "completed":
            report = get_file_report(api_key, file_hash)
            if report and report.get("data"):
                return report.get("data", {})
            raise RuntimeError("Analysis completed but the final file report could not be retrieved yet.")

        time.sleep(poll_interval)
        elapsed += poll_interval

    raise TimeoutError(
        "Analysis polling exceeded maximum wait time (20 minutes). "
        "VirusTotal is still processing. Please try again later."
    )


class VirusTotalScannerApp(ctk.CTk):
    def __init__(self, file_path: Path) -> None:
        super().__init__()

        self.title("VirusTotal File Scanner")
        self.geometry("620x420")
        self.resizable(False, False)

        self.file_path = file_path
        self.api_key = ""
        self.summary: Optional[AnalysisSummary] = None
        self.force_reanalyse = False
        self.is_scanning = False

        self._build_ui()
        self.after(100, self._start_scan)

    def _build_ui(self) -> None:
        """Initializes the UI layout using CustomTkinter components."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.container = ctk.CTkFrame(self, corner_radius=15)
        self.container.grid(row=0, column=0, padx=25, pady=25, sticky="nsew")
        self.container.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            self.container,
            text="Initializing scan...",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        self.status_label.grid(row=0, column=0, pady=(25, 15))

        self.spinner = ctk.CTkProgressBar(self.container, mode="indeterminate")
        self.spinner.grid(row=1, column=0, padx=50, pady=(0, 25), sticky="ew")

        self.result_frame = ctk.CTkFrame(self.container, corner_radius=12, fg_color="transparent")
        self.result_frame.grid(row=2, column=0, sticky="nsew", padx=25, pady=(0, 25))
        self.result_frame.grid_columnconfigure(0, weight=1)

        self.res_file = ctk.CTkLabel(
            self.result_frame,
            text="",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        self.res_info = ctk.CTkLabel(
            self.result_frame,
            text="",
            font=ctk.CTkFont(size=12),
            anchor="w",
        )
        self.res_ratio = ctk.CTkLabel(
            self.result_frame,
            text="",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        )
        self.res_hash = ctk.CTkLabel(
            self.result_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="gray",
            anchor="w",
        )

        self.buttons_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.buttons_frame.grid(row=3, column=0, sticky="ew", padx=25, pady=(0, 25))
        self.buttons_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.scan_again_btn = ctk.CTkButton(
            self.buttons_frame,
            text="Scan Again",
            command=self._on_scan_again,
            state="disabled",
        )
        self.view_report_btn = ctk.CTkButton(
            self.buttons_frame,
            text="View Report",
            command=self._on_view_report,
            state="disabled",
        )
        self.close_btn = ctk.CTkButton(
            self.buttons_frame,
            text="Close",
            command=self.destroy,
        )

        self.scan_again_btn.grid(row=0, column=0, padx=5)
        self.view_report_btn.grid(row=0, column=1, padx=5)
        self.close_btn.grid(row=0, column=2, padx=5)

    def _start_scan(self) -> None:
        """Starts a background scan if one is not already running."""
        if self.is_scanning:
            return

        self.is_scanning = True
        self.spinner.grid()
        self.spinner.start()

        worker = threading.Thread(target=self._scan_worker, daemon=True)
        worker.start()

    def _scan_worker(self) -> None:
        """Background thread handling the VirusTotal workflow."""
        try:
            self.api_key = load_api_key()
            file_hash = sha256_of_file(self.file_path)

            self._update_status_text("Checking existing report...")
            report = get_file_report(self.api_key, file_hash)

            if report and not self.force_reanalyse:
                summary = summarize_report(report.get("data", {}))
                self._update_ui_with_summary(summary)
                return

            if self.force_reanalyse and report:
                self._update_status_text("Triggering re-analysis...")
                analysis_data = reanalyse_file(self.api_key, file_hash)
                analysis_id = analysis_data.get("id")
            else:
                file_size_mb = self.file_path.stat().st_size / (1024 * 1024)

                if file_size_mb > 32:
                    self._update_status_text(
                        f"Uploading large file ({file_size_mb:.1f} MB)...\nThis may take several minutes"
                    )
                else:
                    self._update_status_text("Uploading file...")

                analysis_data = upload_file(self.api_key, self.file_path)
                analysis_id = analysis_data.get("id")

            if not analysis_id:
                raise RuntimeError("Failed to get analysis ID from VirusTotal.")

            self._update_status_text("Analyzing file...\n(This may take a few minutes)")
            final_data = poll_analysis(self.api_key, analysis_id, file_hash)
            summary = summarize_report(final_data)
            self._update_ui_with_summary(summary)

        except Exception as error:
            error_message = str(error)
            self.after(0, lambda: self._handle_error(error_message))
            print(traceback.format_exc())

    def _update_status_text(self, text: str) -> None:
        """Updates the header status text safely from a worker thread."""
        self.after(0, lambda: self.status_label.configure(text=text))

    def _clear_result_display(self) -> None:
        """Clears the current result area."""
        self.result_frame.configure(fg_color="transparent")

        self.res_file.grid_forget()
        self.res_info.grid_forget()
        self.res_ratio.grid_forget()
        self.res_hash.grid_forget()

        self.res_file.configure(text="")
        self.res_info.configure(text="")
        self.res_ratio.configure(text="")
        self.res_hash.configure(text="")

    def _update_ui_with_summary(self, summary: AnalysisSummary) -> None:
        """Updates the UI after a scan is completed successfully."""
        def apply_summary() -> None:
            self.spinner.stop()
            self.spinner.grid_remove()

            self.status_label.configure(text="Analysis complete")

            if summary.malicious > 0:
                bg_color = "#7f1f1f"
            elif summary.suspicious > 0:
                bg_color = "#7f5f1f"
            else:
                bg_color = "#1f5f1f"

            self.result_frame.configure(fg_color=bg_color)

            size_mb = self.file_path.stat().st_size / (1024 * 1024)

            info_parts = [f"Size: {size_mb:.2f} MB"]
            if summary.last_scan_date:
                info_parts.append(f"Last Scan: {summary.last_scan_date} {summary.relative_time}".strip())

            self.res_file.configure(text=f"File: {self.file_path.name}")
            self.res_info.configure(text="  |  ".join(info_parts))
            self.res_ratio.configure(
                text=(
                    f"Detection Ratio: {summary.malicious} / {summary.total_engines} "
                    f"({summary.malicious} Malicious, {summary.suspicious} Suspicious)"
                )
            )
            self.res_hash.configure(text=f"SHA-256: {summary.sha256}")

            self.res_file.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 5))
            self.res_info.grid(row=1, column=0, sticky="w", padx=20, pady=2)
            self.res_ratio.grid(row=2, column=0, sticky="w", padx=20, pady=12)
            self.res_hash.grid(row=3, column=0, sticky="w", padx=20, pady=(0, 20))

            self.summary = summary
            self.force_reanalyse = False
            self.is_scanning = False

            self.scan_again_btn.configure(state="normal")
            if summary.report_url:
                self.view_report_btn.configure(state="normal")
            else:
                self.view_report_btn.configure(state="disabled")

        self.after(0, apply_summary)

    def _handle_error(self, message: str) -> None:
        """Handles scan errors and resets the UI to a usable state."""
        self.spinner.stop()
        self.spinner.grid_remove()

        self.status_label.configure(text=f"Error: {message}")

        self.summary = None
        self.force_reanalyse = False
        self.is_scanning = False

        self.scan_again_btn.configure(state="normal")
        self.view_report_btn.configure(state="disabled")

    def _on_scan_again(self) -> None:
        """Triggers a re-analysis for the current file."""
        if self.is_scanning:
            return

        self.force_reanalyse = True
        self.summary = None

        self.scan_again_btn.configure(state="disabled")
        self.view_report_btn.configure(state="disabled")

        self.status_label.configure(text="Starting new scan...")
        self._clear_result_display()
        self._start_scan()

    def _on_view_report(self) -> None:
        """Opens the VirusTotal report in the default web browser."""
        if not self.summary:
            self.status_label.configure(text="Report is not available yet.")
            return

        url = self.summary.report_url.strip()
        if not url.startswith("https://www.virustotal.com/gui/file/"):
            self.status_label.configure(text="Report URL is not valid.")
            return

        webbrowser.open(url)


def main() -> None:
    parser = argparse.ArgumentParser(description="VirusTotal GUI Scanner")
    parser.add_argument("file", help="The file path to scan")
    args = parser.parse_args()

    file_path = Path(args.file).resolve()
    if not file_path.exists():
        print(f"File not found: {file_path}")
        return

    app = VirusTotalScannerApp(file_path)
    app.mainloop()


if __name__ == "__main__":
    main()