"""Modal screens for provider and search setup."""

from .configuration import ConfigurationDialog
from .providers import ProviderDialog
from .search_engines import SearchEngineDialog, SearchEnginePanel
from .update import UpdateConfirmationDialog

__all__ = [
    "ConfigurationDialog",
    "ProviderDialog",
    "SearchEngineDialog",
    "SearchEnginePanel",
    "UpdateConfirmationDialog",
]
