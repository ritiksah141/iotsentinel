#!/usr/bin/env python3
"""
Report Generation Queue Manager for IoTSentinel

Provides asynchronous report generation with queuing to handle heavy loads
without blocking the main application.
"""

import logging
import uuid
import threading
import queue
import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List
from enum import Enum
from dataclasses import dataclass, asdict
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    """Report generation job status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ReportJob:
    """Represents a report generation job."""
    job_id: str
    template_name: str
    format: str
    parameters: Dict[str, Any]
    status: JobStatus
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result_path: Optional[str] = None
    error_message: Optional[str] = None
    progress: int = 0  # 0-100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class ReportQueue:
    """
    Manages asynchronous report generation with queuing.

    Features:
    - Background worker threads
    - Job status tracking
    - Configurable concurrency limit
    - Priority-based queuing
    - Job persistence
    - Progress tracking
    """

    def __init__(
        self,
        report_builder,
        max_workers: int = 2,
        max_queue_size: int = 100,
        results_dir: str = 'data/reports/generated',
        enable_persistence: bool = True
    ):
        """
        Initialize report queue.

        Args:
            report_builder: ReportBuilder instance
            max_workers: Maximum concurrent workers
            max_queue_size: Maximum queue size
            results_dir: Directory for generated reports
            enable_persistence: Enable job persistence
        """
        self.report_builder = report_builder
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        self.results_dir = Path(results_dir)
        self.enable_persistence = enable_persistence

        # Create results directory
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Job queue and tracking
        self.job_queue = queue.PriorityQueue(maxsize=max_queue_size)
        self.jobs: Dict[str, ReportJob] = {}
        self.jobs_lock = threading.Lock()

        # Worker threads
        self.workers: List[threading.Thread] = []
        self.running = False

        # Start workers
        self.start()

        logger.info(f"Report queue initialized with {max_workers} workers")

    def start(self):
        """Start worker threads."""
        if self.running:
            logger.warning("Workers already running")
            return

        self.running = True

        # Create and start worker threads
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker,
                name=f"ReportWorker-{i+1}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)

        logger.info(f"Started {self.max_workers} report generation workers")

    def stop(self):
        """Stop worker threads gracefully."""
        logger.info("Stopping report generation workers...")
        self.running = False

        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5.0)

        self.workers.clear()
        logger.info("Report generation workers stopped")

    def submit_job(
        self,
        template_name: str,
        format: str,
        parameters: Optional[Dict[str, Any]] = None,
        priority: int = 5
    ) -> str:
        """
        Submit a report generation job.

        Args:
            template_name: Report template name
            format: Output format (pdf, excel, json)
            parameters: Report parameters
            priority: Job priority (1-10, lower = higher priority)

        Returns:
            Job ID

        Raises:
            queue.Full: If queue is full
        """
        # Generate job ID
        job_id = str(uuid.uuid4())

        # Create job
        job = ReportJob(
            job_id=job_id,
            template_name=template_name,
            format=format,
            parameters=parameters or {},
            status=JobStatus.PENDING,
            created_at=datetime.now().isoformat()
        )

        # Add to tracking
        with self.jobs_lock:
            self.jobs[job_id] = job

        # Add to queue (lower priority number = higher priority)
        try:
            self.job_queue.put((priority, job_id), block=False)
            logger.info(f"Job submitted: {job_id} ({template_name}, {format})")
            return job_id

        except queue.Full:
            # Remove from tracking if queue is full
            with self.jobs_lock:
                del self.jobs[job_id]
            raise queue.Full("Report generation queue is full")

    def _worker(self):
        """Worker thread that processes jobs from queue."""
        worker_name = threading.current_thread().name

        while self.running:
            try:
                # Get job from queue (timeout allows checking self.running)
                try:
                    priority, job_id = self.job_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Get job details
                with self.jobs_lock:
                    if job_id not in self.jobs:
                        logger.warning(f"Job {job_id} not found")
                        continue
                    job = self.jobs[job_id]

                # Process job
                logger.info(f"{worker_name}: Processing job {job_id}")
                self._process_job(job)

                # Mark task done
                self.job_queue.task_done()

            except Exception as e:
                logger.error(f"{worker_name}: Error in worker: {e}")

    def _process_job(self, job: ReportJob):
        """
        Process a report generation job.

        Args:
            job: Report job to process
        """
        try:
            # Update status to processing
            with self.jobs_lock:
                job.status = JobStatus.PROCESSING
                job.started_at = datetime.now().isoformat()
                job.progress = 0

            logger.info(f"Generating report: {job.template_name} ({job.format})")

            # Update progress
            self._update_progress(job, 10)

            # Generate report
            report_data = self.report_builder.build_report(
                template_name=job.template_name,
                format=job.format,
                parameters=job.parameters,
                use_cache=True  # Use cache for better performance
            )

            if not report_data:
                raise Exception("Report generation returned None")

            # Update progress
            self._update_progress(job, 80)

            # Save report to disk
            filename = report_data.get('filename', f'report_{job.job_id}.{job.format}')
            result_path = self.results_dir / filename

            content = report_data.get('content')
            if isinstance(content, bytes):
                with open(result_path, 'wb') as f:
                    f.write(content)
            else:
                with open(result_path, 'w') as f:
                    f.write(content)

            # Update progress
            self._update_progress(job, 100)

            # Update job status
            with self.jobs_lock:
                job.status = JobStatus.COMPLETED
                job.completed_at = datetime.now().isoformat()
                job.result_path = str(result_path)
                job.progress = 100

            logger.info(f"Report generated successfully: {job.job_id} -> {result_path}")

        except Exception as e:
            logger.error(f"Error generating report {job.job_id}: {e}")

            # Update job status to failed
            with self.jobs_lock:
                job.status = JobStatus.FAILED
                job.completed_at = datetime.now().isoformat()
                job.error_message = str(e)
                job.progress = 0

    def _update_progress(self, job: ReportJob, progress: int):
        """Update job progress."""
        with self.jobs_lock:
            job.progress = min(progress, 100)

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get job status.

        Args:
            job_id: Job ID

        Returns:
            Job status dictionary or None if not found
        """
        with self.jobs_lock:
            job = self.jobs.get(job_id)
            if job:
                return job.to_dict()
        return None

    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending job.

        Args:
            job_id: Job ID

        Returns:
            True if cancelled, False if not found or already processing
        """
        with self.jobs_lock:
            job = self.jobs.get(job_id)
            if not job:
                return False

            # Can only cancel pending jobs
            if job.status == JobStatus.PENDING:
                job.status = JobStatus.CANCELLED
                job.completed_at = datetime.now().isoformat()
                logger.info(f"Job cancelled: {job_id}")
                return True

        return False

    def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        List jobs with optional filtering.

        Args:
            status: Filter by status (None = all)
            limit: Maximum number of jobs to return

        Returns:
            List of job dictionaries
        """
        with self.jobs_lock:
            jobs_list = list(self.jobs.values())

            # Filter by status
            if status:
                jobs_list = [j for j in jobs_list if j.status == status]

            # Sort by created_at (newest first)
            jobs_list.sort(key=lambda j: j.created_at, reverse=True)

            # Limit results
            jobs_list = jobs_list[:limit]

            return [job.to_dict() for job in jobs_list]

    def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get queue statistics.

        Returns:
            Dictionary with queue statistics
        """
        with self.jobs_lock:
            total_jobs = len(self.jobs)
            status_counts = {}

            for status in JobStatus:
                count = sum(1 for j in self.jobs.values() if j.status == status)
                status_counts[status.value] = count

        return {
            'total_jobs': total_jobs,
            'queue_size': self.job_queue.qsize(),
            'max_queue_size': self.max_queue_size,
            'active_workers': sum(1 for w in self.workers if w.is_alive()),
            'max_workers': self.max_workers,
            'status_breakdown': status_counts,
            'running': self.running
        }

    def cleanup_old_jobs(self, days: int = 7):
        """
        Remove completed/failed jobs older than specified days.

        Args:
            days: Number of days to keep jobs
        """
        cutoff = datetime.now().timestamp() - (days * 24 * 60 * 60)

        with self.jobs_lock:
            jobs_to_remove = []

            for job_id, job in self.jobs.items():
                # Parse created_at timestamp
                try:
                    created_at = datetime.fromisoformat(job.created_at).timestamp()

                    # Remove if old and not pending/processing
                    if created_at < cutoff and job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
                        jobs_to_remove.append(job_id)

                        # Delete result file if exists
                        if job.result_path:
                            try:
                                Path(job.result_path).unlink(missing_ok=True)
                            except Exception as e:
                                logger.warning(f"Could not delete result file: {e}")

                except Exception as e:
                    logger.warning(f"Error parsing job timestamp: {e}")

            # Remove jobs
            for job_id in jobs_to_remove:
                del self.jobs[job_id]

            if jobs_to_remove:
                logger.info(f"Cleaned up {len(jobs_to_remove)} old jobs")
