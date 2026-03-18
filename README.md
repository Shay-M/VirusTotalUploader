# VirusTotal File Uploader CLI

A small Python CLI tool that computes a file's SHA-256 hash, checks VirusTotal for an existing report, and uploads the file if needed.

## Setup

1. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

2. Create a `.env` file (or set `VT_API_KEY` in your environment):

```bash
cp .env.example .env
# then edit .env and set VT_API_KEY
```

## Usage

```bash
python vt_uploader.py "C:\path\to\file.ext"
```

The script will:

- Compute the SHA-256 hash
- Check VirusTotal (GET /files/{hash})
- If a report exists, print a summary
- Otherwise, upload the file (smart upload based on size)
- Poll the analysis until complete
- Print a clean summary of detections
