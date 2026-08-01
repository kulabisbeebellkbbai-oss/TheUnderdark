"""Fixture-safe implementation of TheUnderdark's bounded storage contract."""

from .adapter import Authorization, RootRegistration, StorageAdapter

__all__ = ["Authorization", "RootRegistration", "StorageAdapter"]
__version__ = "0.1.0"
