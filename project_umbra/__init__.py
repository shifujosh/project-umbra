"""
Project Umbra — Autonomous Background OSINT & Digital Footprint Remediation Agent.
"""

__version__ = "1.0.0"
__author__ = "Project Umbra Team"

from project_umbra.config import settings
from project_umbra.core.agent import ProjectUmbraAgent

__all__ = ["settings", "ProjectUmbraAgent", "__version__"]
