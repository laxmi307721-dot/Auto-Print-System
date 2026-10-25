import os
import tempfile
import threading
import time
import requests
from printing import send_to_printer

SERVER_URL = os.environ.get("PRINT_SERVER_URL", "http://localhost:5000").rstrip("/")
PRINT_AGENT_TOKEN = os.environ.get("PRINT_AGENT_TOKEN", "")
POLL_INTERVAL = 30  # seconds

def request_headers():
    if PRINT_AGENT_TOKEN:
        return {"Authorization": f"Bearer {PRINT_AGENT_TOKEN}"}
    return {}

def get_job_to_print():
    try:
        response = requests.get(
            f"{SERVER_URL}/get_next_job",
            headers=request_headers(),
            timeout=15,
        )
        if response.status_code == 200:
            return response.json()
        print(f"Job check failed: HTTP {response.status_code} {response.text}")
    except requests.RequestException as e:
        print(f"Server se sampark nahi ho saka: {e}")
    return None

def print_document(file_path, job=None):
    job = job or {}
    return send_to_printer(
        file_path,
        paper_size=job.get("paper_size", "A4"),
        duplex=job.get("duplex", False),
        copies=job.get("copies", 1),
        print_type=job.get("print_type", "Black & White"),
    )

def update_job_status(job_id, status):
    try:
        response = requests.post(
            f"{SERVER_URL}/update_job_status",
            json={"job_id": job_id, "status": status},
            headers=request_headers(),
            timeout=15,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Status update error: {e}")

def download_job_file(file_url):
    response = requests.get(file_url, stream=True, timeout=60)
    response.raise_for_status()
    temporary_file = tempfile.NamedTemporaryFile(prefix="print-job-", suffix=".pdf", delete=False)
    try:
        with temporary_file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    temporary_file.write(chunk)
        return temporary_file.name
    except Exception:
        os.remove(temporary_file.name)
        raise

def cleanup_temporary_file(file_path):
    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass
    except OSError as e:
        print(f"Temporary print file cleanup failed: {e}")

def run_agent():
    print("Print Agent chal raha hai...")
    while True:
        job = get_job_to_print()
        if job:
            job_id = job.get("id")
            file_path = job.get("file_path")
            temporary_file = None
            if job.get("file_url"):
                try:
                    temporary_file = download_job_file(job["file_url"])
                    file_path = temporary_file
                except requests.RequestException as e:
                    print(f"Job {job_id} download failed: {e}")
                    update_job_status(job_id, "Retry")

            if file_path and os.path.exists(file_path):
                print(f"Job {job_id} print ho raha hai...")
                if print_document(file_path, job):
                    update_job_status(job_id, "Printed")
                    if temporary_file:
                        cleanup_timer = threading.Timer(180, cleanup_temporary_file, args=(temporary_file,))
                        cleanup_timer.daemon = True
                        cleanup_timer.start()
                        temporary_file = None
                else:
                    update_job_status(job_id, "Retry")
            else:
                if not job.get("file_url"):
                    print("File nahi mili ya invalid job.")
                    update_job_status(job_id, "Retry")
            if temporary_file and os.path.exists(temporary_file):
                os.remove(temporary_file)
        
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_agent()