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

# Optional dotenv support to load API keys from a .env file
try:
    from dotenv import load_dotenv
    _HAS_DOTENV = True
except ImportError:
    _HAS_DOTENV = False

# Configuration constants
VT_API_KEY_ENV = "VT_API_KEY"
VT_API_BASE = "https://www.virustotal.com/api/v3"

@dataclass
class AnalysisSummary:
    """Stores a cleaned-up version of the VirusTotal analysis report."""
    sha256: str
    total_engines: int
    malicious: int
    suspicious: int
    report_url: str
    last_scan_date: str = ""
    relative_time: str = ""

def load_api_key() -> str:
    """Retrieves the API key from environment variables or .env file."""
    if _HAS_DOTENV:
        from dotenv import load_dotenv as _load_dotenv_func
        _load_dotenv_func(dotenv_path=".env")
    
    api_key = os.getenv(VT_API_KEY_ENV)
    if not api_key:
        raise RuntimeError(f"VirusTotal API key not found. Please set {VT_API_KEY_ENV}.")
    return api_key.strip()

def sha256_of_file(path: Path, chunk_size: int = 64 * 1024) -> str:
    """Generates a SHA-256 hash of a file efficiently using chunks."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def vt_headers(api_key: str) -> Dict[str, str]:
    """Returns standardized headers for VirusTotal API requests."""
    return {"x-apikey": api_key}

def summarize_report(data: Dict[str, Any]) -> AnalysisSummary:
    """Parses raw VirusTotal JSON data into a clean AnalysisSummary object."""
    attributes = data.get("attributes", {})
    stats = attributes.get("stats", {})
    sha256 = attributes.get("sha256") or attributes.get("md5") or ""
    report_url = f"https://www.virustotal.com/gui/file/{sha256}/detection" if sha256 else ""

    last_scan_str = ""
    rel_time = ""
    
    # Calculate relative time (e.g., '2 days ago')
    if "last_analysis_date" in attributes:
        ts = attributes["last_analysis_date"]
        dt = datetime.fromtimestamp(ts)
        last_scan_str = dt.strftime("%d/%m/%Y %H:%M")
        
        diff = datetime.now() - dt
        if diff.days > 0:
            rel_time = f"({diff.days} days ago)"
        else:
            hours = diff.seconds // 3600
            rel_time = f"({hours} hours ago)" if hours > 0 else "(Just now)"

    return AnalysisSummary(
        sha256=sha256,
        total_engines=sum(stats.values()) if isinstance(stats, dict) else 0,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        report_url=report_url,
        last_scan_date=last_scan_str,
        relative_time=rel_time
    )

# --- VirusTotal API Communication Functions ---

def get_file_report(api_key: str, file_hash: str) -> Optional[Dict[str, Any]]:
    url = f"{VT_API_BASE}/files/{file_hash}"
    resp = requests.get(url, headers=vt_headers(api_key), timeout=60)
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return None

def upload_file(api_key: str, file_path: Path) -> Dict[str, Any]:
    """Uploads a file, supporting large files via a generated upload URL if needed."""
    size = file_path.stat().st_size
    max_size_allowed = 650 * 1024 * 1024  # VirusTotal's limit: ~650MB
    
    if size > max_size_allowed:
        raise RuntimeError(
            f"File size {size / (1024**2):.1f}MB exceeds VirusTotal's limit of 650MB. "
            f"Please use a smaller file."
        )
    
    if size <= 32 * 1024 * 1024:
        url = f"{VT_API_BASE}/files"
        with file_path.open("rb") as f:
            files = {"file": (file_path.name, f)}
            resp = requests.post(url, headers=vt_headers(api_key), files=files, timeout=300)
    else:
        # Request a special upload URL for files larger than 32MB
        resp = requests.get(f"{VT_API_BASE}/files/upload_url", headers=vt_headers(api_key), timeout=60)
        resp.raise_for_status()
        upload_url = resp.json().get("data")
        with file_path.open("rb") as f:
            files = {"file": (file_path.name, f)}
            # Larger timeout for big files (up to 30 minutes)
            resp = requests.post(upload_url, headers=vt_headers(api_key), files=files, timeout=1800)
    
    resp.raise_for_status()
    return resp.json().get("data", {})

def poll_analysis(api_key: str, analysis_id: str) -> Dict[str, Any]:
    """Polls the analysis status until completion with a maximum wait time."""
    url = f"{VT_API_BASE}/analyses/{analysis_id}"
    max_wait_seconds = 1200  # 20 minutes maximum
    elapsed = 0
    poll_interval = 15
    
    while elapsed < max_wait_seconds:
        resp = requests.get(url, headers=vt_headers(api_key), timeout=60)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        if data.get("attributes", {}).get("status") == "completed":
            # Analysis is complete, fetch the full file report now
            file_id = data.get("meta", {}).get("file_info", {}).get("sha256")
            report = get_file_report(api_key, file_id)
            return report.get("data", {}) if report else {}
        time.sleep(poll_interval)
        elapsed += poll_interval
    
    raise TimeoutError(
        "Analysis polling exceeded maximum wait time (20 minutes). "
        "VirusTotal is still processing. Please try again later."
    )

def reanalyse_file(api_key: str, file_hash: str) -> Dict[str, Any]:
    url = f"{VT_API_BASE}/files/{file_hash}/analyse"
    resp = requests.post(url, headers=vt_headers(api_key), timeout=60)
    resp.raise_for_status()
    return resp.json().get("data", {})

# --- GUI Application ---

class VirusTotalScannerApp(ctk.CTk):
    def __init__(self, file_path: Path) -> None:
        super().__init__()
        self.title("VirusTotal File Scanner")
        self.geometry("620x420")
        self.resizable(False, False)

        self.file_path = file_path
        self.api_key = ""
        self.summary: Optional[AnalysisSummary] = None
        self.force_upload = False

        self._build_ui()
        self.after(100, self._start_scan)

    def _build_ui(self) -> None:
        """Initializes the UI layout using CustomTkinter components."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.container = ctk.CTkFrame(self, corner_radius=15)
        self.container.grid(row=0, column=0, padx=25, pady=25, sticky="nsew")
        self.container.grid_columnconfigure(0, weight=1)

        # Status Label (The Header)
        self.status_label = ctk.CTkLabel(
            self.container, text="Initializing Scan...", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.status_label.grid(row=0, column=0, pady=(25, 15))

        # Progress Spinner
        self.spinner = ctk.CTkProgressBar(self.container, mode="indeterminate")
        self.spinner.grid(row=1, column=0, padx=50, pady=(0, 25), sticky="ew")

        # Results Display Area
        self.result_frame = ctk.CTkFrame(self.container, corner_radius=12, fg_color="transparent")
        self.result_frame.grid(row=2, column=0, sticky="nsew", padx=25, pady=(0, 25))
        self.result_frame.grid_columnconfigure(0, weight=1)

        # Result Labels (Hidden initially)
        self.res_file = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
        self.res_info = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=12), anchor="w")
        self.res_ratio = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=13, weight="bold"), anchor="w")
        self.res_hash = ctk.CTkLabel(self.result_frame, text="", font=ctk.CTkFont(size=11), text_color="gray", anchor="w")

        # Control Buttons
        self.buttons_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.buttons_frame.grid(row=3, column=0, sticky="ew", padx=25, pady=(0, 25))
        self.buttons_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.scan_again_btn = ctk.CTkButton(self.buttons_frame, text="Scan Again", command=self._on_scan_again, state="disabled")
        self.view_report_btn = ctk.CTkButton(self.buttons_frame, text="View Report", command=self._on_view_report, state="disabled")
        self.close_btn = ctk.CTkButton(self.buttons_frame, text="Close", command=self.destroy)

        self.scan_again_btn.grid(row=0, column=0, padx=5)
        self.view_report_btn.grid(row=0, column=1, padx=5)
        self.close_btn.grid(row=0, column=2, padx=5)

    def _start_scan(self) -> None:
        self.spinner.start()
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        """Background thread handling the actual VT logic."""
        try:
            self.api_key = load_api_key()
            file_hash = sha256_of_file(self.file_path)
            
            # 1. Check for existing report
            report = get_file_report(self.api_key, file_hash)
            
            if report and not self.force_upload:
                summary = summarize_report(report.get("data", {}))
                self._update_ui_with_summary(summary)
                return

            # 2. Force re-analysis or upload new file
            if self.force_upload and report:
                self._update_status_text("Triggering re-analysis...")
                reanal_data = reanalyse_file(self.api_key, file_hash)
                analysis_id = reanal_data.get("id")
            else:
                # Check file size and provide appropriate message
                file_size_mb = self.file_path.stat().st_size / (1024 * 1024)
                if file_size_mb > 32:
                    self._update_status_text(
                        f"Uploading large file ({file_size_mb:.1f}MB)...\nThis may take several minutes"
                    )
                else:
                    self._update_status_text("Uploading file...")
                
                upload_data = upload_file(self.api_key, self.file_path)
                analysis_id = upload_data.get("id")            
            if not analysis_id:
                raise RuntimeError("Failed to get analysis ID from VirusTotal. Please try again.")
            # 3. Wait for VT to finish processing
            self._update_status_text("Analyzing file...\n(This may take a few minutes)")
            final_data = poll_analysis(self.api_key, analysis_id)
            summary = summarize_report(final_data)
            self._update_ui_with_summary(summary)

        except Exception as e:
            self._update_status_text(f"Error: {str(e)}")
            self.after(0, self.spinner.stop)
            print(traceback.format_exc())

    def _update_status_text(self, text: str) -> None:
        self.after(0, lambda: self.status_label.configure(text=text))

    def _update_ui_with_summary(self, summary: AnalysisSummary) -> None:
        """Main UI update after a scan is finished."""
        def _apply():
            self.spinner.stop()
            self.spinner.grid_remove()  # Hide progress bar on completion
            
            # Header Update
            self.status_label.configure(text="Analysis Complete")
            
            # Background Color logic (Green for clean, Red for malicious)
            bg_color = "#1f5f1f" if summary.malicious == 0 else "#7f1f1f"
            self.result_frame.configure(fg_color=bg_color)

            # Metadata calculations
            size_mb = self.file_path.stat().st_size / (1024 * 1024)

            # Populate Labels
            self.res_file.configure(text=f"File: {self.file_path.name}")
            self.res_info.configure(text=f"Size: {size_mb:.2f} MB  |  Last Scan: {summary.last_scan_date} {summary.relative_time}")
            self.res_ratio.configure(text=f"Detection Ratio: {summary.malicious} / {summary.total_engines} ({summary.malicious} Malicious, {summary.suspicious} Suspicious)")
            self.res_hash.configure(text=f"SHA-256: {summary.sha256}")

            # Layout display
            self.res_file.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 5))
            self.res_info.grid(row=1, column=0, sticky="w", padx=20, pady=2)
            self.res_ratio.grid(row=2, column=0, sticky="w", padx=20, pady=12)
            self.res_hash.grid(row=3, column=0, sticky="w", padx=20, pady=(0, 20))

            self.scan_again_btn.configure(state="normal")
            self.view_report_btn.configure(state="normal")
            self.summary = summary
            self.force_upload = False

        self.after(0, _apply)

    def _on_scan_again(self) -> None:
        self.force_upload = True
        self.scan_again_btn.configure(state="disabled")
        self.view_report_btn.configure(state="disabled")
        
        # Reset UI for re-scan
        self.result_frame.configure(fg_color="transparent")
        for widget in self.result_frame.winfo_children():
            widget.grid_forget()
        
        self.spinner.grid()
        self._start_scan()

    def _on_view_report(self) -> None:
        if self.summary:
            webbrowser.open(self.summary.report_url)

def main():
    parser = argparse.ArgumentParser(description="VirusTotal GUI Scanner")
    parser.add_argument("file", help="The file path to scan")
    args = parser.parse_args()

    fpath = Path(args.file).resolve()
    if not fpath.exists():
        print(f"File not found: {fpath}")
        return

    app = VirusTotalScannerApp(fpath)
    app.mainloop()

if __name__ == "__main__":
    main()