"""Automated Remediation & Hardening Playbook Engine."""

from .dispatcher import apply_plan
from .models import HardeningPlan
from .rollback import generate_rollback
from .store import PlanStore
from .syntax import validate_syntax
from .synth import build_all_plans, build_plan, detect_platforms, synthesize, synthesize_all

__all__ = [
    "HardeningPlan",
    "PlanStore",
    "apply_plan",
    "build_all_plans",
    "build_plan",
    "detect_platforms",
    "generate_rollback",
    "synthesize",
    "synthesize_all",
    "validate_syntax",
]
