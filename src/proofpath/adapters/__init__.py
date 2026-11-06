"""Adapter exports. Only Nmap is registered by the application."""

from proofpath.adapters.base import ToolResult, execute_action
from proofpath.adapters.nmap import NmapAdapter

__all__ = ["NmapAdapter", "ToolResult", "execute_action"]
