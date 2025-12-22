#!/usr/bin/env python3
"""
Performance Optimization Test Script
Tests all implemented optimizations
"""
import time
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print("=" * 60)
print("IoTSentinel Performance Optimization Test")
print("=" * 60)

# Test 1: Connection Pool
print("\n[1/5] Testing Database Connection Pool...")
try:
    from utils.db_pool import get_db_pool, PooledConnection
    pool = get_db_pool()
    print(f"   ✅ Pool initialized with {pool.pool_size} connections")
    print(f"   ✅ Created {pool._created_connections} connections")

    # Test pooled connection
    with PooledConnection(pool) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM devices")
        count = cursor.fetchone()[0]
        print(f"   ✅ Pool connection works! Found {count} devices")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 2: Cached Queries
print("\n[2/5] Testing Query Caching...")
try:
    from utils.cached_queries import get_latest_alerts, get_bandwidth_stats, get_threats_blocked

    # First call - hits database
    start = time.time()
    alerts = get_latest_alerts(10)
    first_call = (time.time() - start) * 1000

    # Second call - should be cached
    start = time.time()
    alerts_cached = get_latest_alerts(10)
    second_call = (time.time() - start) * 1000

    speedup = first_call / second_call if second_call > 0 else float('inf')

    print(f"   ✅ First call (DB):    {first_call:.2f}ms")
    print(f"   ✅ Second call (cache): {second_call:.2f}ms")
    print(f"   ✅ Speedup: {speedup:.1f}x faster")

    # Test other cached functions
    bandwidth = get_bandwidth_stats()
    threats = get_threats_blocked()
    print(f"   ✅ Bandwidth: {bandwidth['formatted']}")
    print(f"   ✅ Threats blocked: {threats}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 3: Import check
print("\n[3/5] Testing App Imports...")
try:
    from dashboard.app import app
    print("   ✅ Dashboard app imports successfully")
    print(f"   ✅ Compress enabled: {app.config.get('compress', False)}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 4: Check refresh interval
print("\n[4/5] Testing Refresh Interval Setting...")
try:
    # Read app.py to check interval setting
    app_path = project_root / "dashboard" / "app.py"
    with open(app_path, 'r') as f:
        content = f.read()
        if 'interval=30*1000' in content:
            print("   ✅ Refresh interval set to 30 seconds (optimized)")
        elif 'interval=10*1000' in content:
            print("   ⚠️  Refresh interval still at 10 seconds (not optimized)")
        else:
            print("   ❓ Could not find refresh interval setting")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 5: Check prevent_initial_call usage
print("\n[5/5] Testing Lazy Loading (prevent_initial_call)...")
try:
    app_path = project_root / "dashboard" / "app.py"
    with open(app_path, 'r') as f:
        content = f.read()

    # Count prevent_initial_call occurrences
    prevent_count = content.count('prevent_initial_call=True')
    print(f"   ✅ Found {prevent_count} callbacks with prevent_initial_call=True")

    # Check specific important callbacks
    checks = [
        ("update_network_graph_3d", "3D Network Graph"),
        ("update_network_graph", "2D Network Graph"),
        ("update_traffic_timeline", "Traffic Timeline"),
        ("update_protocol_pie", "Protocol Chart"),
        ("update_header_stats", "Header Stats"),
        ("update_system_metrics", "System Metrics"),
    ]

    optimized = 0
    for func_name, display_name in checks:
        # Simple check if prevent_initial_call appears near the function
        if func_name in content:
            func_start = content.find(f"def {func_name}")
            callback_start = content.rfind("@app.callback", 0, func_start)
            callback_section = content[callback_start:func_start]

            if "prevent_initial_call=True" in callback_section:
                print(f"   ✅ {display_name} - Lazy loaded")
                optimized += 1
            else:
                print(f"   ⚠️  {display_name} - Not lazy loaded")

    print(f"\n   Summary: {optimized}/{len(checks)} important callbacks optimized")

except Exception as e:
    print(f"   ❌ Error: {e}")

# Summary
print("\n" + "=" * 60)
print("Test Complete!")
print("=" * 60)
print("\nTo see visual optimizations:")
print("1. Start dashboard: python dashboard/app.py")
print("2. Open browser: http://localhost:8050")
print("3. Press F12 for console and check for:")
print("   - 'Detected refresh rate' message (~100ms after load)")
print("   - Loading spinners on graphs")
print("   - Pagination on Device Management")
print("=" * 60)
