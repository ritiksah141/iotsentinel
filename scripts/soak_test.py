import psutil
import time
import csv
from datetime import datetime
from pathlib import Path

DURATION_HOURS = 24
INTERVAL_SECONDS = 60

# Ensure the log directory exists
log_dir = Path('data/logs')
log_dir.mkdir(parents=True, exist_ok=True)
output_file = log_dir / 'soak_test_results.csv'

print(f"Starting {DURATION_HOURS}h soak test. Results will be saved to {output_file}")

with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp', 'cpu_percent', 'ram_percent', 'disk_percent'])

    end_time = time.time() + (DURATION_HOURS * 3600)

    try:
        while time.time() < end_time:
            row = [
                datetime.now().isoformat(),
                psutil.cpu_percent(),
                psutil.virtual_memory().percent,
                psutil.disk_usage('/').percent
            ]
            writer.writerow(row)
            f.flush() # Ensure data is written to disk immediately
            print(f"Logged: CPU={row[1]}%, RAM={row[2]}%, Disk={row[3]}%")
            time.sleep(INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("Test stopped manually.")
    finally:
        print(f"Soak test finished. Results saved to {output_file}")
