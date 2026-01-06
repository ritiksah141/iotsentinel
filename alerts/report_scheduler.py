#!/usr/bin/env python3
"""
Report Scheduler for IoTSentinel

Handles scheduled generation and sending of security reports:
- Weekly summary reports (every Sunday at 9 AM)
- Monthly trend reports (1st of each month at 9 AM)

Uses APScheduler for reliable scheduling with persistence support.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable, List
from threading import Thread, Event

logger = logging.getLogger(__name__)

# Try to import APScheduler, fall back to simple scheduler if not available
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False
    logger.warning("APScheduler not installed. Using simple scheduler fallback.")
    logger.info("Install APScheduler for production: pip install apscheduler")


class ReportGenerator:
    """
    Generates security report data for email notifications.

    Aggregates data from the database to create comprehensive
    weekly and monthly reports.
    """

    def __init__(self, db_manager, alert_service):
        """
        Initialize the report generator.

        Args:
            db_manager: Database manager instance
            alert_service: AlertService instance for summary data
        """
        self.db = db_manager
        self.alert_service = alert_service

    def generate_weekly_report(self) -> Dict[str, Any]:
        """
        Generate weekly security report data.

        Returns:
            Dictionary containing report data
        """
        # Calculate date range (last 7 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)

        # Get alert summary for the week
        summary = self.alert_service.get_alert_summary(hours=168)  # 7 days = 168 hours

        # Get top alerts (critical and high only)
        top_alerts = self._get_top_alerts(hours=168, limit=10)

        # Get network statistics
        network_stats = self._get_network_stats(hours=168)

        return {
            'report_type': 'weekly',
            'period': f"{start_date.strftime('%B %d')} - {end_date.strftime('%B %d, %Y')}",
            'generated_at': datetime.now().isoformat(),
            'summary': summary,
            'top_alerts': top_alerts,
            'network_stats': network_stats,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        }

    def generate_monthly_report(self) -> Dict[str, Any]:
        """
        Generate monthly security report data.

        Returns:
            Dictionary containing report data
        """
        # Calculate date range (last 30 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)

        # Get alert summary for the month
        summary = self.alert_service.get_alert_summary(hours=720)  # 30 days = 720 hours

        # Get top alerts
        top_alerts = self._get_top_alerts(hours=720, limit=15)

        # Get network statistics
        network_stats = self._get_network_stats(hours=720)

        # Get trend data (weekly breakdown)
        trends = self._get_weekly_trends()

        return {
            'report_type': 'monthly',
            'period': f"{start_date.strftime('%B %d')} - {end_date.strftime('%B %d, %Y')}",
            'generated_at': datetime.now().isoformat(),
            'summary': summary,
            'top_alerts': top_alerts,
            'network_stats': network_stats,
            'trends': trends,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        }

    def _get_top_alerts(self, hours: int, limit: int = 10) -> list:
        """Get top priority alerts from the time period."""
        try:
            alerts = self.db.get_recent_alerts(hours=hours)

            # Sort by severity (critical first) then by score
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_alerts = sorted(
                alerts,
                key=lambda x: (
                    severity_order.get(x.get('severity', 'low'), 4),
                    -abs(x.get('anomaly_score', 0))
                )
            )

            return sorted_alerts[:limit]

        except Exception as e:
            logger.error(f"Error getting top alerts: {e}")
            return []

    def _get_network_stats(self, hours: int) -> Dict[str, Any]:
        """Get network statistics for the time period."""
        try:
            # Get device count
            devices = self.db.get_all_devices()
            device_count = len(devices) if devices else 0

            # Get connection statistics
            conn_stats = self._calculate_connection_stats(hours)

            return {
                'total_devices': device_count,
                'total_connections': conn_stats.get('count', 'N/A'),
                'data_transferred': self._format_bytes(conn_stats.get('total_bytes', 0)),
                'unique_destinations': conn_stats.get('unique_destinations', 'N/A')
            }

        except Exception as e:
            logger.error(f"Error getting network stats: {e}")
            return {
                'total_devices': 'N/A',
                'total_connections': 'N/A',
                'data_transferred': 'N/A',
                'unique_destinations': 'N/A'
            }

    def _calculate_connection_stats(self, hours: int) -> Dict[str, Any]:
        """Calculate connection statistics from database."""
        try:
            cursor = self.db.conn.cursor()
            cutoff = datetime.now() - timedelta(hours=hours)

            # Get connection count and bytes
            cursor.execute("""
                SELECT
                    COUNT(*) as count,
                    COALESCE(SUM(bytes_sent), 0) + COALESCE(SUM(bytes_received), 0) as total_bytes,
                    COUNT(DISTINCT dest_ip) as unique_destinations
                FROM connections
                WHERE timestamp > ?
            """, (cutoff.isoformat(),))

            row = cursor.fetchone()

            return {
                'count': row['count'] if row else 0,
                'total_bytes': row['total_bytes'] if row else 0,
                'unique_destinations': row['unique_destinations'] if row else 0
            }

        except Exception as e:
            logger.error(f"Error calculating connection stats: {e}")
            return {'count': 0, 'total_bytes': 0, 'unique_destinations': 0}

    def _get_weekly_trends(self) -> list:
        """Get weekly alert trends for the past month."""
        try:
            trends = []

            for week in range(4):
                start = datetime.now() - timedelta(days=(week + 1) * 7)
                end = datetime.now() - timedelta(days=week * 7)

                # Count alerts in this week
                cursor = self.db.conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) as count,
                           SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) as high_priority
                    FROM alerts
                    WHERE timestamp BETWEEN ? AND ?
                """, (start.isoformat(), end.isoformat()))

                row = cursor.fetchone()

                trends.append({
                    'week': f"Week {4 - week}",
                    'period': f"{start.strftime('%m/%d')} - {end.strftime('%m/%d')}",
                    'total_alerts': row['count'] if row else 0,
                    'high_priority': row['high_priority'] if row else 0
                })

            return trends[::-1]  # Reverse to show oldest first

        except Exception as e:
            logger.error(f"Error getting weekly trends: {e}")
            return []

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes into human-readable string."""
        if bytes_val is None:
            return "N/A"

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024

        return f"{bytes_val:.1f} PB"


class SimpleScheduler:
    """
    Simple fallback scheduler when APScheduler is not available.

    Uses basic threading to schedule report generation.
    Less robust than APScheduler but functional for basic needs.
    """

    def __init__(self):
        self._stop_event = Event()
        self._jobs: Dict[str, Dict] = {}
        self._thread: Optional[Thread] = None

    def add_job(self, func: Callable, job_id: str, **kwargs):
        """Add a scheduled job."""
        self._jobs[job_id] = {
            'func': func,
            'kwargs': kwargs,
            'last_run': None
        }
        logger.info(f"Added job: {job_id}")

    def start(self):
        """Start the scheduler."""
        self._stop_event.clear()
        self._thread = Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Simple scheduler started")

    def shutdown(self, wait: bool = True):
        """Stop the scheduler."""
        self._stop_event.set()
        if self._thread and wait:
            self._thread.join(timeout=5)
        logger.info("Simple scheduler stopped")

    def _run_loop(self):
        """Main scheduler loop."""
        import time

        while not self._stop_event.is_set():
            now = datetime.now()

            for job_id, job in self._jobs.items():
                if self._should_run(job_id, job, now):
                    try:
                        logger.info(f"Running scheduled job: {job_id}")
                        job['func']()
                        job['last_run'] = now
                    except Exception as e:
                        logger.error(f"Error running job {job_id}: {e}")

            # Sleep for 1 minute between checks
            self._stop_event.wait(60)

    def _should_run(self, job_id: str, job: Dict, now: datetime) -> bool:
        """Check if a job should run based on simple schedule."""
        last_run = job.get('last_run')

        # Weekly report: Sunday at 9 AM
        if 'weekly' in job_id:
            if now.weekday() == 6 and now.hour == 9:
                if last_run is None or (now - last_run).days >= 1:
                    return True

        # Monthly report: 1st of month at 9 AM
        if 'monthly' in job_id:
            if now.day == 1 and now.hour == 9:
                if last_run is None or (now - last_run).days >= 1:
                    return True

        return False


class ReportScheduler:
    """
    Manages scheduled report generation and delivery.

    Uses APScheduler for production deployments or falls back
    to SimpleScheduler if APScheduler is not installed.

    Supports:
    - Weekly/monthly security reports
    - Custom template-based reports
    - PDF/Excel email attachments
    - Daily digest emails
    """

    def __init__(self, db_manager, alert_service, notification_dispatcher, db_path: str = None, email_notifier=None):
        """
        Initialize the report scheduler.

        Args:
            db_manager: Database manager instance
            alert_service: AlertService instance
            notification_dispatcher: NotificationDispatcher for sending reports
            db_path: Optional database path for enhanced email attachments
            email_notifier: Optional EmailNotifier instance with attachment support
        """
        self.report_generator = ReportGenerator(db_manager, alert_service)
        self.dispatcher = notification_dispatcher
        self.db_path = db_path or getattr(db_manager, 'db_path', None)

        # Use provided email_notifier or try to get from dispatcher handlers
        self.email_notifier = email_notifier
        if not self.email_notifier and self.db_path:
            try:
                # Try to get email handler from dispatcher
                email_handler = notification_dispatcher._handlers.get('email')
                if email_handler and hasattr(email_handler, 'config'):
                    # Import and initialize enhanced notifier with db_path
                    from alerts.email_notifier import EmailNotifier
                    self.email_notifier = EmailNotifier(email_handler.config, db_path=self.db_path)
                    logger.info("Enhanced email notifier initialized with attachment support")
            except Exception as e:
                logger.warning(f"Could not initialize enhanced email notifier: {e}")

        # Initialize scheduler
        if APSCHEDULER_AVAILABLE:
            self._scheduler = BackgroundScheduler()
            self._setup_apscheduler_jobs()
        else:
            self._scheduler = SimpleScheduler()
            self._setup_simple_jobs()

        self._running = False
        self._paused_jobs = set()  # Track paused job IDs
        logger.info("ReportScheduler initialized")

    def _setup_apscheduler_jobs(self):
        """Set up jobs using APScheduler."""
        # Weekly report: Every Sunday at 9:00 AM
        self._scheduler.add_job(
            self._send_weekly_report,
            CronTrigger(day_of_week='sun', hour=9, minute=0),
            id='weekly_report',
            name='Weekly Security Report',
            replace_existing=True
        )

        # Monthly report: 1st of each month at 9:00 AM
        self._scheduler.add_job(
            self._send_monthly_report,
            CronTrigger(day=1, hour=9, minute=0),
            id='monthly_report',
            name='Monthly Security Report',
            replace_existing=True
        )

        logger.info("APScheduler jobs configured")

    def _setup_simple_jobs(self):
        """Set up jobs using simple scheduler."""
        self._scheduler.add_job(
            self._send_weekly_report,
            job_id='weekly_report'
        )
        self._scheduler.add_job(
            self._send_monthly_report,
            job_id='monthly_report'
        )

        logger.info("Simple scheduler jobs configured")

    def start(self):
        """Start the scheduler."""
        if not self._running:
            self._scheduler.start()
            self._running = True
            logger.info("Report scheduler started")

    def stop(self):
        """Stop the scheduler."""
        if self._running:
            self._scheduler.shutdown(wait=True)
            self._running = False
            logger.info("Report scheduler stopped")

    def _send_weekly_report(self):
        """Generate and send weekly report."""
        try:
            logger.info("Generating weekly security report...")
            report_data = self.report_generator.generate_weekly_report()

            results = self.dispatcher.dispatch_report(report_data)

            success_count = sum(1 for r in results if r.success)
            logger.info(f"Weekly report sent to {success_count}/{len(results)} channels")

        except Exception as e:
            logger.error(f"Error sending weekly report: {e}", exc_info=True)

    def _send_monthly_report(self):
        """Generate and send monthly report."""
        try:
            logger.info("Generating monthly security report...")
            report_data = self.report_generator.generate_monthly_report()

            results = self.dispatcher.dispatch_report(report_data)

            success_count = sum(1 for r in results if r.success)
            logger.info(f"Monthly report sent to {success_count}/{len(results)} channels")

        except Exception as e:
            logger.error(f"Error sending monthly report: {e}", exc_info=True)

    def send_report_now(self, report_type: str = 'weekly') -> bool:
        """
        Manually trigger a report send (for testing or on-demand).

        Args:
            report_type: 'weekly' or 'monthly'

        Returns:
            True if at least one channel succeeded
        """
        try:
            if report_type == 'weekly':
                self._send_weekly_report()
            elif report_type == 'monthly':
                self._send_monthly_report()
            else:
                logger.error(f"Unknown report type: {report_type}")
                return False

            return True

        except Exception as e:
            logger.error(f"Error sending {report_type} report: {e}")
            return False

    # ==================== Enhanced Custom Scheduling ====================

    def add_custom_schedule(
        self,
        schedule_id: str,
        template_name: str,
        cron_expression: str = None,
        interval_hours: int = None,
        format: str = 'pdf',
        parameters: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Add a custom scheduled report using templates.

        Args:
            schedule_id: Unique identifier for this schedule
            template_name: Name of the report template to use
            cron_expression: Cron expression (e.g., '0 9 * * 1' for Monday 9am)
            interval_hours: Alternative to cron - run every N hours
            format: Report format ('pdf', 'excel', 'json')
            parameters: Optional parameters for template

        Returns:
            True if schedule added successfully

        Examples:
            # Daily executive summary at 8am
            add_custom_schedule('daily_exec', 'executive_summary',
                              cron_expression='0 8 * * *')

            # Security audit every 6 hours
            add_custom_schedule('hourly_security', 'security_audit',
                              interval_hours=6)
        """
        try:
            if not APSCHEDULER_AVAILABLE:
                logger.warning("Custom schedules require APScheduler")
                return False

            # Lazy import report_builder
            from utils.report_builder import ReportBuilder

            def generate_and_send():
                try:
                    logger.info(f"Generating custom report: {schedule_id}")

                    # Use enhanced email notifier if available
                    if self.email_notifier and (format in ['pdf', 'excel']):
                        # Send report with attachment using enhanced notifier
                        result = self.email_notifier.send_report_with_attachment(
                            template_name=template_name,
                            format=format,
                            days=parameters.get('days', 7) if parameters else 7,
                            recipient=parameters.get('recipient') if parameters else None
                        )

                        if result.success:
                            logger.info(f"Custom report {schedule_id} emailed successfully with {format.upper()} attachment")
                        else:
                            logger.error(f"Failed to email custom report {schedule_id}: {result.error}")

                    else:
                        # Fall back to traditional dispatch method
                        builder = ReportBuilder(self.db_path or self.report_generator.db.db_path)
                        report = builder.build_report(
                            template_name=template_name,
                            format=format,
                            parameters=parameters or {}
                        )

                        if report:
                            logger.info(f"Custom report generated: {report['filename']}")

                            # If dispatcher has send_custom_report method, use it
                            if hasattr(self.dispatcher, 'send_custom_report'):
                                results = self.dispatcher.send_custom_report(
                                    report,
                                    schedule_id=schedule_id,
                                    template_name=template_name
                                )
                                success_count = sum(1 for r in results if r.success)
                                logger.info(f"Custom report sent to {success_count}/{len(results)} channels")
                        else:
                            logger.error(f"Failed to generate custom report: {schedule_id}")

                except Exception as e:
                    logger.error(f"Error in custom report job {schedule_id}: {e}")

            # Add job with appropriate trigger
            if cron_expression:
                # Parse cron expression (minute hour day month day_of_week)
                parts = cron_expression.split()
                if len(parts) != 5:
                    logger.error(f"Invalid cron expression: {cron_expression}")
                    return False

                trigger = CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4]
                )

                self._scheduler.add_job(
                    generate_and_send,
                    trigger=trigger,
                    id=schedule_id,
                    name=f"Custom Report: {template_name}",
                    replace_existing=True
                )

            elif interval_hours:
                from apscheduler.triggers.interval import IntervalTrigger

                self._scheduler.add_job(
                    generate_and_send,
                    IntervalTrigger(hours=interval_hours),
                    id=schedule_id,
                    name=f"Custom Report: {template_name} (every {interval_hours}h)",
                    replace_existing=True
                )

            else:
                logger.error("Must provide either cron_expression or interval_hours")
                return False

            logger.info(f"Added custom schedule: {schedule_id} for template {template_name}")
            return True

        except Exception as e:
            logger.error(f"Error adding custom schedule: {e}")
            return False

    def remove_custom_schedule(self, schedule_id: str) -> bool:
        """
        Remove a custom scheduled report.

        Args:
            schedule_id: ID of schedule to remove

        Returns:
            True if removed successfully
        """
        try:
            if not APSCHEDULER_AVAILABLE:
                return False

            self._scheduler.remove_job(schedule_id)
            self._paused_jobs.discard(schedule_id)  # Clean up paused state if present
            logger.info(f"Removed custom schedule: {schedule_id}")
            return True

        except Exception as e:
            logger.error(f"Error removing custom schedule: {e}")
            return False

    def list_schedules(self) -> List[Dict[str, Any]]:
        """
        List all scheduled jobs.

        Returns:
            List of schedule information dictionaries
        """
        try:
            if not APSCHEDULER_AVAILABLE:
                return []

            schedules = []
            for job in self._scheduler.get_jobs():
                schedules.append({
                    'id': job.id,
                    'name': job.name,
                    'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                    'trigger': str(job.trigger),
                    'paused': job.id in self._paused_jobs  # Include paused state
                })

            return schedules

        except Exception as e:
            logger.error(f"Error listing schedules: {e}")
            return []

    def pause_schedule(self, schedule_id: str) -> bool:
        """
        Pause a scheduled job.

        Args:
            schedule_id: ID of schedule to pause

        Returns:
            True if paused successfully
        """
        try:
            if not APSCHEDULER_AVAILABLE:
                return False

            self._scheduler.pause_job(schedule_id)
            self._paused_jobs.add(schedule_id)  # Track paused state
            logger.info(f"Paused schedule: {schedule_id}")
            return True

        except Exception as e:
            logger.error(f"Error pausing schedule: {e}")
            return False

    def resume_schedule(self, schedule_id: str) -> bool:
        """
        Resume a paused scheduled job.

        Args:
            schedule_id: ID of schedule to resume

        Returns:
            True if resumed successfully
        """
        try:
            if not APSCHEDULER_AVAILABLE:
                return False

            self._scheduler.resume_job(schedule_id)
            self._paused_jobs.discard(schedule_id)  # Remove from paused set
            logger.info(f"Resumed schedule: {schedule_id}")
            return True

        except Exception as e:
            logger.error(f"Error resuming schedule: {e}")
            return False

    def get_schedule_info(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific schedule.

        Args:
            schedule_id: ID of schedule

        Returns:
            Schedule information dictionary or None
        """
        try:
            if not APSCHEDULER_AVAILABLE:
                return None

            job = self._scheduler.get_job(schedule_id)
            if not job:
                return None

            return {
                'id': job.id,
                'name': job.name,
                'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                'trigger': str(job.trigger),
                'pending': job.pending
            }

        except Exception as e:
            logger.error(f"Error getting schedule info: {e}")
            return None

    def add_daily_digest_schedule(
        self,
        hour: int = 8,
        minute: int = 0,
        recipient: str = None
    ) -> bool:
        """
        Schedule daily security digest email.

        Args:
            hour: Hour of day to send (0-23), default 8am
            minute: Minute of hour (0-59), default 0
            recipient: Optional email recipient override

        Returns:
            True if schedule added successfully

        Example:
            # Send daily digest at 8:00 AM
            add_daily_digest_schedule(hour=8, minute=0)
        """
        try:
            if not self.email_notifier:
                logger.error("Daily digest requires enhanced email notifier")
                return False

            if not APSCHEDULER_AVAILABLE:
                logger.warning("Daily digest scheduling requires APScheduler")
                return False

            def send_digest():
                try:
                    logger.info("Sending daily security digest...")
                    result = self.email_notifier.send_daily_digest(recipient=recipient)

                    if result.success:
                        logger.info("Daily digest sent successfully")
                    else:
                        logger.error(f"Failed to send daily digest: {result.error}")

                except Exception as e:
                    logger.error(f"Error sending daily digest: {e}")

            # Add job with cron trigger
            self._scheduler.add_job(
                send_digest,
                CronTrigger(hour=hour, minute=minute),
                id='daily_digest',
                name='Daily Security Digest',
                replace_existing=True
            )

            logger.info(f"Daily digest scheduled for {hour:02d}:{minute:02d} daily")
            return True

        except Exception as e:
            logger.error(f"Error scheduling daily digest: {e}")
            return False

    def send_digest_now(self, recipient: str = None) -> bool:
        """
        Manually send daily digest (for testing).

        Args:
            recipient: Optional email recipient override

        Returns:
            True if sent successfully
        """
        try:
            if not self.email_notifier:
                logger.error("Daily digest requires enhanced email notifier")
                return False

            result = self.email_notifier.send_daily_digest(recipient=recipient)

            if result.success:
                logger.info("Daily digest sent successfully")
                return True
            else:
                logger.error(f"Failed to send daily digest: {result.error}")
                return False

        except Exception as e:
            logger.error(f"Error sending daily digest: {e}")
            return False
