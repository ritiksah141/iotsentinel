#!/usr/bin/env python3
"""
Advanced System Metrics Collector for IoTSentinel

Collects comprehensive metrics for:
- Performance monitoring (CPU, RAM, latency)
- ML model performance (precision, recall, F1)
- Data pipeline throughput
- System health indicators

Generates evidence for AT3 Evaluation section.

Usage:
    python3 utils/metrics_collector.py --start
    python3 utils/metrics_collector.py --report
"""

import psutil
import time
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager


class MetricsCollector:
    """Comprehensive metrics collection and reporting."""
    
    def __init__(self):
        self.db = DatabaseManager(config.get('database', 'path'))
        self.metrics_file = Path('data/logs/metrics.json')
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.metrics = {
            'system': [],
            'pipeline': [],
            'ml_performance': []
        }
        
        self._load_metrics()
    
    def _load_metrics(self):
        """Load existing metrics from file."""
        if self.metrics_file.exists():
            with open(self.metrics_file, 'r') as f:
                self.metrics = json.load(f)
    
    def _save_metrics(self):
        """Save metrics to file."""
        with open(self.metrics_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
    
    def collect_system_metrics(self):
        """Collect system resource metrics."""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get Zeek process stats if running
        zeek_stats = self._get_zeek_stats()
        
        metric = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': cpu_percent,
            'cpu_count': psutil.cpu_count(),
            'memory_used_mb': memory.used / (1024 ** 2),
            'memory_total_mb': memory.total / (1024 ** 2),
            'memory_percent': memory.percent,
            'disk_used_gb': disk.used / (1024 ** 3),
            'disk_free_gb': disk.free / (1024 ** 3),
            'disk_percent': disk.percent,
            'zeek_running': zeek_stats['running'],
            'zeek_cpu': zeek_stats.get('cpu', 0),
            'zeek_memory_mb': zeek_stats.get('memory_mb', 0)
        }
        
        self.metrics['system'].append(metric)
        self._save_metrics()
        
        return metric
    
    def _get_zeek_stats(self):
        """Get Zeek process statistics."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                if 'zeek' in proc.info['name'].lower():
                    return {
                        'running': True,
                        'cpu': proc.info['cpu_percent'],
                        'memory_mb': proc.info['memory_info'].rss / (1024 ** 2)
                    }
        except:
            pass
        
        return {'running': False}
    
    def collect_pipeline_metrics(self):
        """Collect data pipeline metrics."""
        cursor = self.db.conn.cursor()
        
        # Connection throughput (last hour)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM connections
            WHERE timestamp > datetime('now', '-1 hour')
        """)
        connections_hour = cursor.fetchone()['count']
        
        # Unprocessed connections
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM connections
            WHERE processed = 0
        """)
        unprocessed = cursor.fetchone()['count']
        
        # Processing lag (oldest unprocessed)
        cursor.execute("""
            SELECT 
                CAST((julianday('now') - julianday(MIN(timestamp))) * 24 * 60 AS INTEGER) as lag_minutes
            FROM connections
            WHERE processed = 0
        """)
        result = cursor.fetchone()
        lag_minutes = result['lag_minutes'] if result['lag_minutes'] else 0
        
        # Alert rate
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-1 hour')
        """)
        alerts_hour = cursor.fetchone()['count']
        
        metric = {
            'timestamp': datetime.now().isoformat(),
            'connections_per_hour': connections_hour,
            'unprocessed_connections': unprocessed,
            'processing_lag_minutes': lag_minutes,
            'alerts_per_hour': alerts_hour,
            'anomaly_rate': (alerts_hour / connections_hour * 100) if connections_hour > 0 else 0
        }
        
        self.metrics['pipeline'].append(metric)
        self._save_metrics()
        
        return metric
    
    def collect_ml_performance_metrics(self):
        """Collect ML model performance metrics."""
        cursor = self.db.conn.cursor()
        
        # Get predictions from last 24 hours
        cursor.execute("""
            SELECT 
                model_type,
                COUNT(*) as total,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                AVG(anomaly_score) as avg_score,
                MIN(anomaly_score) as min_score,
                MAX(anomaly_score) as max_score
            FROM ml_predictions
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY model_type
        """)
        
        results = cursor.fetchall()
        
        model_metrics = []
        for row in results:
            model_metrics.append({
                'model_type': row['model_type'],
                'total_predictions': row['total'],
                'anomalies_detected': row['anomalies'],
                'anomaly_rate': (row['anomalies'] / row['total'] * 100) if row['total'] > 0 else 0,
                'avg_anomaly_score': row['avg_score'],
                'score_range': [row['min_score'], row['max_score']]
            })
        
        metric = {
            'timestamp': datetime.now().isoformat(),
            'models': model_metrics
        }
        
        self.metrics['ml_performance'].append(metric)
        self._save_metrics()
        
        return metric
    
    def generate_performance_report(self):
        """Generate comprehensive performance report for AT3."""
        print("\n" + "=" * 70)
        print(" " * 15 + "IoTSentinel Performance Report")
        print("=" * 70)
        
        # System Performance
        print("\n📊 SYSTEM PERFORMANCE")
        print("-" * 70)
        
        if self.metrics['system']:
            recent_system = self.metrics['system'][-20:]  # Last 20 samples
            avg_cpu = sum(m['cpu_percent'] for m in recent_system) / len(recent_system)
            avg_memory = sum(m['memory_percent'] for m in recent_system) / len(recent_system)
            avg_zeek_cpu = sum(m.get('zeek_cpu', 0) for m in recent_system) / len(recent_system)
            
            print(f"Average CPU Usage:        {avg_cpu:.1f}%")
            print(f"Average Memory Usage:     {avg_memory:.1f}%")
            print(f"Zeek CPU Usage:           {avg_zeek_cpu:.1f}%")
            print(f"CPU Cores:                {recent_system[-1]['cpu_count']}")
            print(f"Total RAM:                {recent_system[-1]['memory_total_mb']:.0f} MB")
            
            # Performance classification
            if avg_cpu < 30 and avg_memory < 60:
                status = "✅ EXCELLENT - Well within capacity"
            elif avg_cpu < 50 and avg_memory < 75:
                status = "✓ GOOD - Acceptable performance"
            else:
                status = "⚠️  HIGH - Consider optimization"
            
            print(f"\nPerformance Status:       {status}")
        else:
            print("No system metrics collected yet.")
        
        # Pipeline Performance
        print("\n🔄 DATA PIPELINE PERFORMANCE")
        print("-" * 70)
        
        if self.metrics['pipeline']:
            recent_pipeline = self.metrics['pipeline'][-20:]
            avg_throughput = sum(m['connections_per_hour'] for m in recent_pipeline) / len(recent_pipeline)
            avg_lag = sum(m['processing_lag_minutes'] for m in recent_pipeline) / len(recent_pipeline)
            avg_anomaly_rate = sum(m['anomaly_rate'] for m in recent_pipeline) / len(recent_pipeline)
            
            print(f"Avg Connections/Hour:     {avg_throughput:.0f}")
            print(f"Avg Processing Lag:       {avg_lag:.1f} minutes")
            print(f"Avg Anomaly Rate:         {avg_anomaly_rate:.2f}%")
            print(f"Current Unprocessed:      {recent_pipeline[-1]['unprocessed_connections']}")
            
            # Throughput classification
            if avg_throughput > 100:
                throughput_status = "✅ HIGH - Good network activity"
            elif avg_throughput > 50:
                throughput_status = "✓ MODERATE - Normal activity"
            else:
                throughput_status = "⚠️  LOW - Limited activity"
            
            print(f"\nThroughput Status:        {throughput_status}")
        else:
            print("No pipeline metrics collected yet.")
        
        # ML Performance
        print("\n🤖 MACHINE LEARNING PERFORMANCE")
        print("-" * 70)
        
        if self.metrics['ml_performance'] and self.metrics['ml_performance'][-1]['models']:
            latest_ml = self.metrics['ml_performance'][-1]
            
            for model in latest_ml['models']:
                print(f"\n{model['model_type'].upper()}:")
                print(f"  Total Predictions:      {model['total_predictions']:,}")
                print(f"  Anomalies Detected:     {model['anomalies_detected']:,}")
                print(f"  Anomaly Rate:           {model['anomaly_rate']:.2f}%")
                print(f"  Avg Anomaly Score:      {model['avg_anomaly_score']:.4f}")
                print(f"  Score Range:            {model['score_range']}")
        else:
            print("No ML performance metrics collected yet.")
        
        # Generate Summary Statistics
        print("\n📈 SUMMARY STATISTICS (FOR AT3 EVALUATION)")
        print("-" * 70)
        
        cursor = self.db.conn.cursor()
        
        # Total connections processed
        cursor.execute("SELECT COUNT(*) FROM connections")
        total_connections = cursor.fetchone()[0]
        
        # Total alerts generated
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]
        
        # Total devices seen
        cursor.execute("SELECT COUNT(*) FROM devices")
        total_devices = cursor.fetchone()[0]
        
        # Uptime estimate (first to last connection)
        cursor.execute("""
            SELECT 
                MIN(timestamp) as first_conn,
                MAX(timestamp) as last_conn
            FROM connections
        """)
        result = cursor.fetchone()
        
        if result['first_conn'] and result['last_conn']:
            first = datetime.fromisoformat(result['first_conn'])
            last = datetime.fromisoformat(result['last_conn'])
            uptime_hours = (last - first).total_seconds() / 3600
        else:
            uptime_hours = 0
        
        print(f"Total Connections:        {total_connections:,}")
        print(f"Total Alerts:             {total_alerts:,}")
        print(f"Total Devices:            {total_devices:,}")
        print(f"System Uptime:            {uptime_hours:.1f} hours")
        
        if total_connections > 0:
            print(f"Alert Rate:               {(total_alerts/total_connections*100):.2f}%")
        
        print("\n" + "=" * 70)
        print("\n💡 Use these metrics in your AT3 Evaluation section!")
        print("=" * 70)
        
        # Return structured data for programmatic use
        return {
            'system': {
                'avg_cpu': avg_cpu if self.metrics['system'] else 0,
                'avg_memory': avg_memory if self.metrics['system'] else 0,
                'avg_zeek_cpu': avg_zeek_cpu if self.metrics['system'] else 0
            },
            'pipeline': {
                'avg_throughput': avg_throughput if self.metrics['pipeline'] else 0,
                'avg_lag': avg_lag if self.metrics['pipeline'] else 0,
                'avg_anomaly_rate': avg_anomaly_rate if self.metrics['pipeline'] else 0
            },
            'totals': {
                'connections': total_connections,
                'alerts': total_alerts,
                'devices': total_devices,
                'uptime_hours': uptime_hours
            }
        }
    
    def monitor_continuous(self, interval=60):
        """Continuously monitor and collect metrics."""
        print(f"Starting continuous monitoring (interval: {interval}s)")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Collecting metrics...")
                
                system_metric = self.collect_system_metrics()
                print(f"  CPU: {system_metric['cpu_percent']:.1f}% | "
                      f"RAM: {system_metric['memory_percent']:.1f}%")
                
                pipeline_metric = self.collect_pipeline_metrics()
                print(f"  Connections/hr: {pipeline_metric['connections_per_hour']} | "
                      f"Unprocessed: {pipeline_metric['unprocessed_connections']}")
                
                ml_metric = self.collect_ml_performance_metrics()
                if ml_metric['models']:
                    for model in ml_metric['models']:
                        print(f"  {model['model_type']}: "
                              f"{model['anomalies_detected']}/{model['total_predictions']} anomalies")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped.")
            print("Generating final report...\n")
            self.generate_performance_report()


def main():
    """CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description='IoTSentinel Metrics Collector')
    parser.add_argument('--start', action='store_true', help='Start continuous monitoring')
    parser.add_argument('--report', action='store_true', help='Generate performance report')
    parser.add_argument('--interval', type=int, default=60, help='Collection interval (seconds)')
    parser.add_argument('--once', action='store_true', help='Collect metrics once')
    
    args = parser.parse_args()
    
    collector = MetricsCollector()
    
    if args.start:
        collector.monitor_continuous(interval=args.interval)
    elif args.report:
        collector.generate_performance_report()
    elif args.once:
        print("Collecting metrics...")
        collector.collect_system_metrics()
        collector.collect_pipeline_metrics()
        collector.collect_ml_performance_metrics()
        print("✓ Metrics collected")
    else:
        print("Use --start for continuous monitoring or --report to generate report")


if __name__ == '__main__':
    main()