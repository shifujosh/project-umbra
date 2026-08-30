"""
Dynamic persistence repository resolver.
Auto-resolves between Google Cloud Firestore and local SQLite with seamless fallback.
"""

from __future__ import annotations

import logging
import os
from typing import Literal

from project_umbra.config import settings
from project_umbra.storage.base import BasePersistenceRepository
from project_umbra.storage.sqlite import SQLitePersistenceRepository

logger = logging.getLogger(__name__)

_DEFAULT_REPOSITORY: BasePersistenceRepository | None = None


def get_persistence_repository(
    mode: Literal["auto", "firestore", "sqlite"] | str | None = None,
    db_path: str | None = None,
    project_id: str | None = None,
    database: str | None = None,
) -> BasePersistenceRepository:
    """
    Factory function resolving the active persistence repository backend.

    Resolution Strategy:
    1. If mode == 'sqlite' -> returns SQLitePersistenceRepository.
    2. If mode == 'firestore' -> instantiates FirestorePersistenceRepository.
    3. If mode == 'auto' (default) -> probes GCP credentials / environment.
       If GCP Firestore is reachable and configured, returns FirestorePersistenceRepository.
       Otherwise, gracefully falls back to SQLitePersistenceRepository.
    """
    resolved_mode = (mode or settings.PERSISTENCE_MODE).lower()

    if resolved_mode == "sqlite":
        logger.debug("Explicit SQLite persistence repository requested.")
        return SQLitePersistenceRepository(db_path=db_path)

    if resolved_mode == "firestore":
        logger.debug("Explicit Firestore persistence repository requested.")
        from project_umbra.storage.firestore import FirestorePersistenceRepository
        return FirestorePersistenceRepository(
            project_id=project_id or settings.GCP_PROJECT_ID,
            database=database or settings.FIRESTORE_DATABASE,
        )

    # AUTO MODE: Probe GCP environment and credentials
    is_cloud_run = bool(os.environ.get("K_SERVICE") or os.environ.get("GOOGLE_CLOUD_PROJECT"))
    try:
        sa_creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        has_sa_file = bool(sa_creds and os.path.exists(sa_creds))
        target_project = project_id or settings.GCP_PROJECT_ID

        if not has_sa_file and not is_cloud_run:
            logger.info("Local environment without GCP credentials. Auto-resolving to SQLitePersistenceRepository.")
            return SQLitePersistenceRepository(db_path=db_path)

        from project_umbra.storage.firestore import FirestorePersistenceRepository
        repo = FirestorePersistenceRepository(
            project_id=target_project,
            database=database or settings.FIRESTORE_DATABASE,
        )
        return repo

    except (ImportError, Exception) as err:
        if resolved_mode == "firestore" or is_cloud_run or settings.ENVIRONMENT == "production":
            logger.error(
                "Firestore is required in production and failed to initialize (%s)",
                type(err).__name__,
            )
            raise
        logger.warning(
            "GCP Firestore resolution failed (%s). Falling back to local SQLitePersistenceRepository.",
            type(err).__name__,
        )
        return SQLitePersistenceRepository(db_path=db_path)


def get_storage_repository(
    mode: Literal["auto", "firestore", "sqlite"] | str | None = None,
    db_path: str | None = None,
    project_id: str | None = None,
    database: str | None = None,
) -> BasePersistenceRepository:
    """Alias for get_persistence_repository."""
    return get_persistence_repository(mode=mode, db_path=db_path, project_id=project_id, database=database)


async def get_default_repository() -> BasePersistenceRepository:
    """Returns the singleton persistence repository instance, initializing it if necessary."""
    global _DEFAULT_REPOSITORY
    if _DEFAULT_REPOSITORY is None:
        _DEFAULT_REPOSITORY = get_persistence_repository()
        await _DEFAULT_REPOSITORY.initialize()
    return _DEFAULT_REPOSITORY


async def reset_default_repository() -> None:
    """Closes and resets the singleton repository instance (useful for test isolation)."""
    global _DEFAULT_REPOSITORY
    if _DEFAULT_REPOSITORY is not None:
        await _DEFAULT_REPOSITORY.close()
        _DEFAULT_REPOSITORY = None
