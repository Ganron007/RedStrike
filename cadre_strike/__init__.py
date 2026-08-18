"""Deprecated import path. Use `import redstrike`."""

from __future__ import annotations

import warnings

from redstrike import __version__ as __version__

warnings.warn(
    "The 'cadre_strike' package was renamed to 'redstrike'. Update imports.",
    DeprecationWarning,
    stacklevel=2,
)
