# IoTSentinel API Reference

**Version**: 1.0
**Base URL**: `http://<raspberry-pi-ip>:8050`
**Protocol**: HTTP/HTTPS
**Authentication**: Session-based (login required for most endpoints)

---

## 📋 Table of Contents

1. [Authentication](#authentication)
2. [Health & Monitoring](#health--monitoring)
3. [Dashboard Endpoints](#dashboard-endpoints)
4. [Device Management](#device-management)
5. [Alert Management](#alert-management)
6. [Analytics & Reports](#analytics--reports)
7. [System Configuration](#system-configuration)
8. [WebSocket Updates](#websocket-updates)

---

## 🔐 Authentication

### Login

**Endpoint**: `POST /login`

**Description**: Authenticate user and create session

**Request**:
```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=your_password
```

**Response** (Success):
```http
HTTP/1.1 302 Found
Location: /
Set-Cookie: session=...; HttpOnly; Path=/
```

**Response** (Failure - Invalid Credentials):
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html

Invalid username or password
```

**Response** (Failure - Rate Limited):
```http
HTTP/1.1 429 Too Many Requests
Content-Type: text/html

Too many failed attempts. Please try again in 5 minutes.
```

**Rate Limiting**:
- **Limit**: 5 failed attempts per IP
- **Lockout Duration**: 5 minutes
- **Implementation**: `utils/rate_limiter.py`

---

### Logout

**Endpoint**: `POST /logout`

**Description**: End user session

**Request**:
```http
POST /logout HTTP/1.1
Cookie: session=...
```

**Response**:
```http
HTTP/1.1 302 Found
Location: /login
Set-Cookie: session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT
```

---

## 🏥 Health & Monitoring

### Health Check

**Endpoint**: `GET /health`

**Description**: System health status (no authentication required)

**Request**:
```http
GET /health HTTP/1.1
```

**Response** (Healthy):
```json
{
  "status": "healthy",
  "timestamp": "2025-12-16T01:30:00Z",
  "version": "1.0.0",
  "components": {
    "database": {
      "status": "up",
      "response_time_ms": 12
    },
    "zeek_parser": {
      "status": "running",
      "last_activity": "2025-12-16T01:29:45Z"
    },
    "ml_engine": {
      "status": "ready",
      "models_loaded": true
    },
    "alerting": {
      "status": "active"
    }
  },
  "system": {
    "cpu_percent": 42.3,
    "memory_percent": 67.8,
    "disk_percent": 45.2,
    "uptime_hours": 168.5
  }
}
```

**Response** (Degraded):
```json
{
  "status": "degraded",
  "timestamp": "2025-12-16T01:30:00Z",
  "components": {
    "database": {
      "status": "up"
    },
    "zeek_parser": {
      "status": "stopped",
      "error": "Zeek service not running"
    }
  }
}
```

**HTTP Status Codes**:
- `200 OK`: All components healthy
- `503 Service Unavailable`: One or more critical components down

**Implementation**: `dashboard/app.py:88-155`

---

## 📊 Dashboard Endpoints

### Main Dashboard

**Endpoint**: `GET /`

**Description**: Main dashboard page with device list, alerts, and analytics

**Authentication**: Required

**Request**:
```http
GET / HTTP/1.1
Cookie: session=...
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
  <!-- Dashboard HTML -->
</html>
```

**Features Displayed**:
- Device list with status indicators
- Real-time alert feed
- Network activity heatmap
- Alert timeline (7 days)
- System health metrics

---

### Get Dashboard Data (AJAX)

**Endpoint**: `POST /_dash-update-component`

**Description**: Dash internal endpoint for component updates (WebSocket-like)

**Authentication**: Required

**Request**:
```json
{
  "output": "device-table.data",
  "inputs": [],
  "state": []
}
```

**Response**:
```json
{
  "response": {
    "device-table": {
      "data": [
        {
          "ip": "192.168.1.100",
          "name": "Living Room Camera",
          "type": "Camera",
          "status": "Active",
          "last_seen": "2 minutes ago"
        }
      ]
    }
  }
}
```

**Note**: This is a Dash framework internal endpoint. For direct API access, use the endpoints below.

---

## 🖥️ Device Management

### Get All Devices

**Endpoint**: `GET /api/devices`

**Description**: Retrieve list of all discovered devices

**Authentication**: Required

**Request**:
```http
GET /api/devices HTTP/1.1
Cookie: session=...
```

**Response**:
```json
{
  "devices": [
    {
      "id": 1,
      "ip": "192.168.1.100",
      "mac": "AA:BB:CC:DD:EE:FF",
      "hostname": "camera-living-room",
      "device_type": "Camera",
      "manufacturer": "Ring",
      "custom_name": "Living Room Camera",
      "first_seen": "2025-12-01T10:30:00Z",
      "last_seen": "2025-12-16T01:28:00Z",
      "status": "active",
      "total_connections": 1523,
      "data_sent_mb": 45.2,
      "data_received_mb": 128.7
    }
  ],
  "total": 12,
  "timestamp": "2025-12-16T01:30:00Z"
}
```

**Query Parameters**:
- `status` (optional): Filter by status (`active`, `inactive`)
- `type` (optional): Filter by device type (`Camera`, `Speaker`, etc.)

**Example**:
```http
GET /api/devices?status=active&type=Camera HTTP/1.1
```

---

### Update Device

**Endpoint**: `POST /api/devices/{device_ip}`

**Description**: Update device custom name, notes, or group

**Authentication**: Required

**Request**:
```json
{
  "custom_name": "Kitchen Camera",
  "notes": "Monitors kitchen entrance",
  "group": "Security Cameras"
}
```

**Response** (Success):
```json
{
  "success": true,
  "device_ip": "192.168.1.100",
  "updated_fields": ["custom_name", "notes", "group"]
}
```

**HTTP Status Codes**:
- `200 OK`: Device updated successfully
- `404 Not Found`: Device IP not found
- `400 Bad Request`: Invalid input data

---

### Block Device

**Endpoint**: `POST /api/devices/{device_ip}/block`

**Description**: Block device using firewall rules

**Authentication**: Required (admin role)

**Request**:
```json
{
  "reason": "Suspicious activity detected",
  "duration_hours": 24
}
```

**Response** (Success):
```json
{
  "success": true,
  "device_ip": "192.168.1.100",
  "blocked": true,
  "unblock_at": "2025-12-17T01:30:00Z"
}
```

**Note**: Requires `scripts/firewall_manager.py` configured

---

## 🚨 Alert Management

### Get Alerts

**Endpoint**: `GET /api/alerts`

**Description**: Retrieve recent alerts

**Authentication**: Required

**Request**:
```http
GET /api/alerts?severity=critical&limit=50 HTTP/1.1
Cookie: session=...
```

**Query Parameters**:
- `severity` (optional): Filter by severity (`critical`, `high`, `medium`, `low`)
- `limit` (optional): Maximum alerts to return (default: 100)
- `acknowledged` (optional): Filter by acknowledgment status (`true`, `false`)
- `days` (optional): Number of days to look back (default: 7)

**Response**:
```json
{
  "alerts": [
    {
      "id": 42,
      "device_ip": "192.168.1.100",
      "device_name": "Living Room Camera",
      "severity": "critical",
      "anomaly_score": 0.98,
      "timestamp": "2025-12-16T01:15:00Z",
      "explanation": {
        "summary": "Device sent 500MB of data in 1 hour (normal: 10MB/hour)",
        "top_features": [
          {
            "feature": "bytes_sent",
            "value": 524288000,
            "normal_range": "5000000-15000000"
          },
          {
            "feature": "connection_count",
            "value": 45,
            "normal_range": "5-10"
          }
        ],
        "contributing_factors": [
          "Unusual data volume",
          "High connection frequency",
          "Destination: unknown IP"
        ]
      },
      "acknowledged": false,
      "acknowledged_by": null,
      "acknowledged_at": null
    }
  ],
  "total": 1,
  "unacknowledged_count": 1
}
```

---

### Acknowledge Alert

**Endpoint**: `POST /api/alerts/{alert_id}/acknowledge`

**Description**: Mark alert as acknowledged

**Authentication**: Required

**Request**:
```json
{
  "notes": "Investigated - firmware update in progress"
}
```

**Response**:
```json
{
  "success": true,
  "alert_id": 42,
  "acknowledged": true,
  "acknowledged_by": "admin",
  "acknowledged_at": "2025-12-16T01:30:00Z"
}
```

---

## 📈 Analytics & Reports

### Get Network Statistics

**Endpoint**: `GET /api/analytics/network-stats`

**Description**: Overall network statistics

**Authentication**: Required

**Request**:
```http
GET /api/analytics/network-stats?days=7 HTTP/1.1
```

**Response**:
```json
{
  "period": {
    "start": "2025-12-09T00:00:00Z",
    "end": "2025-12-16T00:00:00Z",
    "days": 7
  },
  "devices": {
    "total": 12,
    "active": 10,
    "inactive": 2
  },
  "connections": {
    "total": 15234,
    "avg_per_day": 2176,
    "anomalous": 12,
    "anomaly_rate": 0.08
  },
  "traffic": {
    "total_mb": 1523.4,
    "upload_mb": 432.1,
    "download_mb": 1091.3
  },
  "alerts": {
    "total": 12,
    "critical": 1,
    "high": 3,
    "medium": 6,
    "low": 2
  }
}
```

---

### Export Data (CSV)

**Endpoint**: `GET /api/export/{data_type}`

**Description**: Export data as CSV

**Authentication**: Required

**Data Types**: `connections`, `alerts`, `devices`

**Request**:
```http
GET /api/export/connections?start_date=2025-12-01&end_date=2025-12-16 HTTP/1.1
```

**Query Parameters**:
- `start_date` (required): Start date (YYYY-MM-DD)
- `end_date` (required): End date (YYYY-MM-DD)

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/csv
Content-Disposition: attachment; filename="connections_2025-12-01_2025-12-16.csv"

timestamp,device_ip,dest_ip,dest_port,protocol,bytes_sent,bytes_received,duration
2025-12-16T01:00:00Z,192.168.1.100,8.8.8.8,443,tcp,1234,5678,45.2
...
```

**Implementation**: `dashboard/app.py:434-449`

---

## ⚙️ System Configuration

### Get System Status

**Endpoint**: `GET /api/system/status`

**Description**: Current system status and metrics

**Authentication**: Required

**Response**:
```json
{
  "monitoring": {
    "enabled": true,
    "paused": false
  },
  "components": {
    "zeek": {
      "running": true,
      "last_log": "2025-12-16T01:29:45Z"
    },
    "ml_engine": {
      "running": true,
      "models_loaded": true,
      "last_inference": "2025-12-16T01:29:30Z"
    },
    "database": {
      "size_mb": 245.7,
      "connections_count": 15234,
      "oldest_record": "2025-11-16T00:00:00Z"
    }
  },
  "system_metrics": {
    "cpu_percent": 42.3,
    "memory_percent": 67.8,
    "disk_percent": 45.2,
    "temperature_celsius": 58.4
  }
}
```

---

### Pause/Resume Monitoring

**Endpoint**: `POST /api/system/monitoring`

**Description**: Pause or resume network monitoring

**Authentication**: Required (admin role)

**Request** (Pause):
```json
{
  "action": "pause"
}
```

**Response**:
```json
{
  "success": true,
  "monitoring_enabled": false,
  "message": "Monitoring paused. Zeek and ML inference stopped."
}
```

**Request** (Resume):
```json
{
  "action": "resume"
}
```

**Response**:
```json
{
  "success": true,
  "monitoring_enabled": true,
  "message": "Monitoring resumed. Zeek and ML inference started."
}
```

**Implementation**: `dashboard/app.py:167-207`

---

## 🔄 WebSocket Updates

### Real-Time Updates

**Description**: Dashboard uses Dash's built-in WebSocket for real-time updates

**Endpoint**: `ws://<raspberry-pi-ip>:8050/_dash-update-component`

**Update Frequency**: Every 5 seconds (configurable)

**Updated Components**:
- Device table
- Alert feed
- Network activity charts
- System health metrics

**Example WebSocket Message** (Device Update):
```json
{
  "output": "device-table.data",
  "response": {
    "props": {
      "data": [
        {
          "ip": "192.168.1.100",
          "status": "Active",
          "last_seen": "Just now"
        }
      ]
    }
  }
}
```

**Note**: WebSocket connection managed automatically by Dash framework

---

## 🔒 Security

### Authentication

All endpoints except `/login` and `/health` require authentication.

**Session Management**:
- Sessions stored server-side
- `HttpOnly` cookies prevent XSS
- Secure flag enabled in production (HTTPS)
- Session timeout: 24 hours

### Rate Limiting

**Login Endpoint**:
- 5 failed attempts per IP = 5-minute lockout
- Implementation: `utils/rate_limiter.py`

**API Endpoints**:
- No rate limiting currently (single-user home deployment)
- Future: Consider rate limiting for `/api/*` endpoints

### CSRF Protection

- Built-in Dash CSRF protection
- Automatic CSRF tokens in forms

---

## 📝 Error Responses

### Standard Error Format

```json
{
  "error": true,
  "message": "Device not found",
  "code": "DEVICE_NOT_FOUND",
  "timestamp": "2025-12-16T01:30:00Z"
}
```

### HTTP Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful request |
| 400 | Bad Request | Invalid input data |
| 401 | Unauthorized | Not authenticated |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |
| 503 | Service Unavailable | System component down |

---

## 🛠️ Implementation Notes

### Technology Stack

- **Framework**: Dash (Plotly) - Python web framework
- **Server**: Flask (underlying Dash server)
- **WebSocket**: Dash built-in WebSocket for real-time updates
- **Database**: SQLite (accessed via `database/db_manager.py`)
- **Authentication**: Flask sessions with bcrypt password hashing

### Code Locations

- **Main Dashboard**: `dashboard/app.py` (10,899 lines)
- **Database API**: `database/db_manager.py` (876 lines)
- **Health Endpoint**: `dashboard/app.py:88-155`
- **Authentication**: `dashboard/app.py:43,66,3653-3694`
- **Device Management**: `database/db_manager.py:48-118,380-469`
- **Alert Management**: `alerts/alert_manager.py`

---

## 📚 Additional Resources

- **System Configuration**: See `docs/SYSTEM_CONFIGURATION_MANUAL.md`
- **Deployment Guide**: See deployment documentation
- **Testing**: API endpoints tested in `tests/test_dashboard_api_integration.py`

---

**Last Updated**: December 2025
**Version**: 1.0
**Maintained by**: Ritik Sah
