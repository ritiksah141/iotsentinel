# IoTSentinel Deployment Guide for Raspberry Pi

This guide provides step-by-step instructions for deploying and running the IoTSentinel project on a Raspberry Pi.

## 1. Prerequisites

Before you begin, ensure your Raspberry Pi is set up with the following:

- **Raspberry Pi OS:** A fresh installation of Raspberry Pi OS (64-bit recommended) is advised.
- **Internet Connection:** The Pi needs to be connected to the internet to download software and dependencies.
- **Git:** To clone the project repository.
- **Python 3:** Should be pre-installed on Raspberry Pi OS.
- **Zeek:** The network analysis framework.

**Installing Prerequisites:**

```bash
# Update package lists
sudo apt-get update && sudo apt-get upgrade -y

# Install Git and other essentials
sudo apt-get install -y git python3-venv python3-pip

# Install Zeek (follow the official guide for Raspberry Pi OS)
# https://docs.zeek.org/en/master/install/install.html#installing-on-raspberry-pi
# Example (might need adjustments based on the latest Zeek version):
sudo apt-get install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev swig zlib1g-dev
git clone --recursive https://github.com/zeek/zeek
cd zeek
./configure --disable-broker-testing # Broker tests fail on Pi
make -j$(nproc)
sudo make install
cd ..
```

## 2. Deployment

The easiest way to deploy the code to your Raspberry Pi is to use the provided `deploy_to_pi.sh` script.

**Usage of `deploy_to_pi.sh`:**

1.  **Configure `scripts/deploy_to_pi.sh`:** Open `scripts/deploy_to_pi.sh` and ensure the `PI_USER` and `PI_HOST` variables match your Raspberry Pi's username and hostname/IP address.
2.  **Run the deployment script from your local machine (e.g., Mac/Linux):**

    ```bash
    bash scripts/deploy_to_pi.sh
    ```
    This script will:
    - Check connectivity to your Raspberry Pi.
    - Sync the entire project codebase (excluding development files and data) to the specified path on your Pi.
    - Connect via SSH to your Pi and execute a setup script that:
        - Creates necessary directory structures.
        - Verifies Zeek installation and status (and attempts to deploy if not running).
        - Sets up a Python virtual environment and installs dependencies from `requirements-pi.txt`.
        - Initializes the database if it doesn't already exist.
        - **Installs, reloads, enables, and starts all systemd services** (`iotsentinel-backend.service`, `iotsentinel-dashboard.service`, `iotsentinel-hardware.service`).

## 3. Running the Application (after deployment)

Once the `deploy_to_pi.sh` script has been successfully executed, the IoTSentinel services should be running automatically on your Raspberry Pi.

### Checking Service Status

You can check the status of the deployed services by SSHing into your Raspberry Pi:

```bash
ssh <your-pi-user>@<your-pi-host>
```

Then, run the following commands:

```bash
sudo systemctl status iotsentinel-backend.service
sudo systemctl status iotsentinel-dashboard.service
sudo systemctl status iotsentinel-hardware.service
```

### Accessing the Dashboard

You can access the web dashboard from any browser on your network by navigating to `http://<your-pi-ip>:8050`.

## 4. Soak Testing

To run the soak test script, which will log CPU and memory usage to a CSV file for 24 hours, you can run it in the background on your Raspberry Pi:

1.  **SSH into your Raspberry Pi.**
2.  **Navigate to the project directory:**
    ```bash
    cd ~/iotsentinel
    ```
3.  **Run the soak test in the background:**

    ```bash
    nohup python3 scripts/soak_test.py &
    ```

You can monitor the progress of the soak test by tailing the output file:

```bash
tail -f data/logs/soak_test_results.csv
```

After 24 hours, the `data/logs/soak_test_results.csv` file will contain the performance data. This data is then visualized in the "System" tab of the dashboard.
