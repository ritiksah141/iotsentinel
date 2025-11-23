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

Clone the IoTSentinel project repository to your Raspberry Pi:

```bash
git clone <your-repository-url> iotsentinel
cd iotsentinel
```

## 3. Setup

1.  **Create a Python Virtual Environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2.  **Install Python Dependencies:**

    ```bash
    pip install -r requirements-pi.txt
    ```

3.  **Initialize the Database:**

    The orchestrator now handles this automatically on the first run.

## 4. Running the Application

There are two ways to run the application: manually for testing or as a `systemd` service for production.

### Manual Execution (for testing)

1.  **Start the Orchestrator:**

    ```bash
    python3 orchestrator.py
    ```
    This will start the log parser, ML inference engine, database cleanup, and health checks in separate threads.

2.  **Start the Dashboard:**

    In a separate terminal:
    ```bash
    python3 dashboard/app.py
    ```
    You can then access the dashboard at `http://<your-pi-ip>:8050`.

### Production Execution (using systemd)

For the system to run automatically on boot and be managed by `systemd`, you need to set up the `.service` files.

1.  **Copy the Service Files:**

    ```bash
    sudo cp services/iotsentinel-backend.service /etc/systemd/system/
    sudo cp services/iotsentinel-dashboard.service /etc/systemd/system/
    sudo cp services/iotsentinel-hardware.service /etc/systemd/system/
    ```

2.  **Reload the systemd Daemon:**

    ```bash
    sudo systemctl daemon-reload
    ```

3.  **Enable and Start the Services:**

    ```bash
    sudo systemctl enable --now iotsentinel-backend.service
    sudo systemctl enable --now iotsentinel-dashboard.service
    sudo systemctl enable --now iotsentinel-hardware.service
    ```

4.  **Check the Status of the Services:**

    ```bash
    sudo systemctl status iotsentinel-backend.service
    sudo systemctl status iotsentinel-dashboard.service
    sudo systemctl status iotsentinel-hardware.service
    ```

## 5. Soak Testing

To run the soak test script, which will log CPU and memory usage to a CSV file for 24 hours, you can run it in the background using `nohup`:

```bash
nohup python3 scripts/soak_test.py &
```

You can monitor the progress of the soak test by tailing the output file:

```bash
tail -f data/logs/soak_test_results.csv
```

After 24 hours, the `soak_test_results.csv` file will contain the performance data. This data is then visualized in the "System" tab of the dashboard.
