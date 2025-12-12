"""
Academic Evidence Collection Module
Provides BCS compliance tracking, RTM, risk management, and architecture documentation
"""

from .bcs_compliance import BCSComplianceManager
from .rtm_generator import RTMGenerator
from .risk_register import RiskRegisterManager
from .performance_metrics import PerformanceMetricsCollector
from .c4_generator import C4DiagramGenerator

__all__ = [
    'BCSComplianceManager',
    'RTMGenerator',
    'RiskRegisterManager',
    'PerformanceMetricsCollector',
    'C4DiagramGenerator'
]
