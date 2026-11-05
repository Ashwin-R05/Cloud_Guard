"""Configuration management for CloudGuard scanner."""

import os
from dataclasses import dataclass, field
from typing import List, Optional


def _parse_regions(regions_str: Optional[str]) -> List[str]:
    """Parse comma-separated regions string into a list of cleaned region names."""
    if not regions_str:
        return ["us-east-1"]
    regions = [r.strip() for r in regions_str.split(",") if r.strip()]
    return regions if regions else ["us-east-1"]


@dataclass
class Config:
    """Runtime configuration for CloudGuard.

    Loads values from environment variables with safe defaults.
    """

    aws_profile: Optional[str] = field(
        default_factory=lambda: os.getenv("CLOUDWARD_AWS_PROFILE") or os.getenv("AWS_PROFILE")
    )
    regions: List[str] = field(
        default_factory=lambda: _parse_regions(
            os.getenv("CLOUDWARD_REGIONS") or os.getenv("AWS_REGIONS") or os.getenv("AWS_DEFAULT_REGION")
        )
    )
    output_dir: str = field(
        default_factory=lambda: os.getenv("CLOUDWARD_OUTPUT_DIR", "reports")
    )

    @classmethod
    def load(cls) -> "Config":
        """Factory method to load configuration from environment."""
        return cls()

