"""
Project Umbra Dual-Mode Persistence Architecture.
Exports abstract base interface, SQLite, Firestore implementations, and resolver.
"""

from project_umbra.storage.base import BasePersistenceRepository
from project_umbra.storage.firestore import FirestorePersistenceRepository
from project_umbra.storage.resolver import (
    get_default_repository,
    get_persistence_repository,
    get_storage_repository,
    reset_default_repository,
)
from project_umbra.storage.sqlite import SQLitePersistenceRepository

__all__ = [
    "BasePersistenceRepository",
    "SQLitePersistenceRepository",
    "FirestorePersistenceRepository",
    "get_persistence_repository",
    "get_storage_repository",
    "get_default_repository",
    "reset_default_repository",
]
