#!/usr/bin/env python3
"""
ML Model Versioner for IoTSentinel

Manages ML model versions with timestamps, metadata, and rollback capabilities.
Keeps track of model performance and enables safe deployment of updated models.
"""

import logging
import sqlite3
import shutil
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ModelVersioner:
    """
    Manages ML model versioning and deployment.

    Features:
    - Timestamp-based versioning
    - Model metadata tracking
    - Performance metrics logging
    - Rollback capabilities
    - Automatic cleanup of old versions
    """

    def __init__(
        self,
        db_path: str = 'data/iot_monitor.db',
        models_dir: str = 'data/models',
        versions_dir: str = 'data/models/versions',
        active_dir: str = 'data/models/active',
        keep_versions: int = 5
    ):
        """
        Initialize model versioner.

        Args:
            db_path: Path to database
            models_dir: Base models directory
            versions_dir: Directory for versioned models
            active_dir: Directory for active/production models
            keep_versions: Number of versions to keep
        """
        self.db_path = db_path
        self.models_dir = Path(models_dir)
        self.versions_dir = Path(versions_dir)
        self.active_dir = Path(active_dir)
        self.keep_versions = keep_versions

        # Create directories
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        self.active_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Model versioner initialized (keep {keep_versions} versions)")

    def save_versioned_model(
        self,
        model_type: str,
        model_path: str,
        validation_loss: Optional[float] = None,
        training_samples: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Save a new model version with metadata.

        Args:
            model_type: Type of model (e.g., 'autoencoder', 'isolation_forest')
            model_path: Path to model file to save
            validation_loss: Validation loss metric
            training_samples: Number of training samples
            metadata: Additional metadata dictionary

        Returns:
            Version string (timestamp)
        """
        try:
            # Generate version timestamp
            version = datetime.now().strftime('%Y%m%d_%H%M%S')

            # Determine file extension
            source_path = Path(model_path)
            extension = source_path.suffix

            # Build versioned filename
            versioned_filename = f"{model_type}_v{version}{extension}"
            versioned_path = self.versions_dir / versioned_filename

            # Copy model to versions directory
            shutil.copy2(model_path, versioned_path)

            # Save metadata JSON
            metadata_dict = metadata or {}
            metadata_dict.update({
                'model_type': model_type,
                'version': version,
                'created_at': datetime.now().isoformat(),
                'validation_loss': validation_loss,
                'training_samples': training_samples,
                'file_path': str(versioned_path)
            })

            metadata_file = self.versions_dir / f"{model_type}_v{version}_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata_dict, f, indent=2)

            # Save to database
            self._save_version_to_db(
                model_type=model_type,
                version=version,
                file_path=str(versioned_path),
                validation_loss=validation_loss,
                training_samples=training_samples,
                metadata_json=json.dumps(metadata_dict)
            )

            logger.info(f"Saved model version: {model_type} v{version}")

            # Cleanup old versions
            self._cleanup_old_versions(model_type)

            return version

        except Exception as e:
            logger.error(f"Error saving model version: {e}")
            raise

    def _save_version_to_db(
        self,
        model_type: str,
        version: str,
        file_path: str,
        validation_loss: Optional[float],
        training_samples: Optional[int],
        metadata_json: str
    ):
        """Save model version info to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO model_versions
                (model_type, version, file_path, training_samples, validation_loss,
                 metadata_json, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            ''', (
                model_type,
                version,
                file_path,
                training_samples,
                validation_loss,
                metadata_json,
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error saving version to database: {e}")

    def activate_version(
        self,
        model_type: str,
        version: str
    ) -> bool:
        """
        Activate a specific model version (deploy to production).

        Args:
            model_type: Type of model
            version: Version to activate

        Returns:
            True if successful
        """
        try:
            # Get version info from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT file_path FROM model_versions
                WHERE model_type = ? AND version = ?
            ''', (model_type, version))

            row = cursor.fetchone()

            if not row:
                logger.error(f"Version not found: {model_type} v{version}")
                conn.close()
                return False

            versioned_path = Path(row[0])

            # Deactivate current active version
            cursor.execute('''
                UPDATE model_versions
                SET is_active = 0
                WHERE model_type = ? AND is_active = 1
            ''', (model_type,))

            # Activate new version
            cursor.execute('''
                UPDATE model_versions
                SET is_active = 1
                WHERE model_type = ? AND version = ?
            ''', (model_type, version))

            conn.commit()
            conn.close()

            # Copy to active directory
            extension = versioned_path.suffix
            active_path = self.active_dir / f"{model_type}{extension}"
            shutil.copy2(versioned_path, active_path)

            logger.info(f"Activated model version: {model_type} v{version}")
            return True

        except Exception as e:
            logger.error(f"Error activating version: {e}")
            return False

    def get_active_version(self, model_type: str) -> Optional[str]:
        """
        Get currently active version for a model type.

        Args:
            model_type: Type of model

        Returns:
            Version string or None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT version FROM model_versions
                WHERE model_type = ? AND is_active = 1
            ''', (model_type,))

            row = cursor.fetchone()
            conn.close()

            return row[0] if row else None

        except Exception as e:
            logger.error(f"Error getting active version: {e}")
            return None

    def list_versions(
        self,
        model_type: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        List available versions for a model type.

        Args:
            model_type: Type of model
            limit: Maximum number of versions to return

        Returns:
            List of version dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT model_type, version, file_path, training_samples,
                       validation_loss, is_active, created_at
                FROM model_versions
                WHERE model_type = ?
                ORDER BY created_at DESC
                LIMIT ?
            ''', (model_type, limit))

            versions = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return versions

        except Exception as e:
            logger.error(f"Error listing versions: {e}")
            return []

    def compare_versions(
        self,
        model_type: str,
        version1: str,
        version2: str
    ) -> Dict[str, Any]:
        """
        Compare two model versions.

        Args:
            model_type: Type of model
            version1: First version
            version2: Second version

        Returns:
            Comparison dictionary
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get both versions
            cursor.execute('''
                SELECT * FROM model_versions
                WHERE model_type = ? AND version IN (?, ?)
                ORDER BY created_at
            ''', (model_type, version1, version2))

            versions = [dict(row) for row in cursor.fetchall()]
            conn.close()

            if len(versions) != 2:
                logger.error("Could not find both versions for comparison")
                return {}

            v1, v2 = versions

            comparison = {
                'model_type': model_type,
                'version1': v1,
                'version2': v2,
                'validation_loss_diff': None,
                'samples_diff': None,
                'recommendation': ''
            }

            # Compare validation loss
            if v1['validation_loss'] and v2['validation_loss']:
                diff = v2['validation_loss'] - v1['validation_loss']
                comparison['validation_loss_diff'] = diff

                if diff < -0.05:  # 5% improvement
                    comparison['recommendation'] = 'Version 2 shows significant improvement'
                elif diff > 0.1:  # 10% degradation
                    comparison['recommendation'] = 'Version 2 shows degradation, consider rollback'
                else:
                    comparison['recommendation'] = 'Performance similar, safe to use either'

            # Compare training samples
            if v1['training_samples'] and v2['training_samples']:
                comparison['samples_diff'] = v2['training_samples'] - v1['training_samples']

            return comparison

        except Exception as e:
            logger.error(f"Error comparing versions: {e}")
            return {}

    def rollback_to_version(
        self,
        model_type: str,
        version: str
    ) -> bool:
        """
        Rollback to a previous version.

        Args:
            model_type: Type of model
            version: Version to rollback to

        Returns:
            True if successful
        """
        logger.info(f"Rolling back {model_type} to version {version}")
        return self.activate_version(model_type, version)

    def _cleanup_old_versions(self, model_type: str):
        """
        Remove old model versions, keeping only the most recent ones.

        Args:
            model_type: Type of model
        """
        try:
            versions = self.list_versions(model_type, limit=100)

            if len(versions) <= self.keep_versions:
                return

            # Keep the most recent versions and active version
            to_delete = versions[self.keep_versions:]

            for version_info in to_delete:
                # Skip if active
                if version_info['is_active']:
                    continue

                # Delete file
                file_path = Path(version_info['file_path'])
                if file_path.exists():
                    file_path.unlink()
                    logger.debug(f"Deleted old version file: {file_path}")

                # Delete metadata file
                metadata_file = file_path.parent / f"{file_path.stem}_metadata.json"
                if metadata_file.exists():
                    metadata_file.unlink()

                # Remove from database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM model_versions WHERE model_type = ? AND version = ?",
                    (model_type, version_info['version'])
                )
                conn.commit()
                conn.close()

            logger.info(f"Cleaned up {len(to_delete)} old versions of {model_type}")

        except Exception as e:
            logger.error(f"Error cleaning up old versions: {e}")

    def get_version_stats(self) -> Dict[str, Any]:
        """
        Get statistics about model versions.

        Returns:
            Dictionary with stats
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total versions
            cursor.execute("SELECT COUNT(*) FROM model_versions")
            total_versions = cursor.fetchone()[0]

            # Versions by model type
            cursor.execute('''
                SELECT model_type, COUNT(*)
                FROM model_versions
                GROUP BY model_type
            ''')
            by_type = dict(cursor.fetchall())

            # Active versions
            cursor.execute('''
                SELECT model_type, version
                FROM model_versions
                WHERE is_active = 1
            ''')
            active_versions = dict(cursor.fetchall())

            conn.close()

            return {
                'total_versions': total_versions,
                'by_model_type': by_type,
                'active_versions': active_versions
            }

        except Exception as e:
            logger.error(f"Error getting version stats: {e}")
            return {}


# Global model versioner instance
_model_versioner = None


def get_model_versioner(db_path: str = 'data/iot_monitor.db') -> ModelVersioner:
    """
    Get global model versioner instance.

    Args:
        db_path: Path to database

    Returns:
        ModelVersioner instance
    """
    global _model_versioner
    if _model_versioner is None:
        _model_versioner = ModelVersioner(db_path=db_path)
    return _model_versioner
