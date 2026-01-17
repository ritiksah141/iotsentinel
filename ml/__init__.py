"""
IoTSentinel ML Package - River-based Incremental Learning

Active Components:
- RiverMLEngine: Incremental learning engine (replaces TensorFlow)
- InferenceEngine: Main anomaly detection orchestrator
- SmartRecommender: Context-aware security recommendations
- TrafficForecaster: 24-hour bandwidth prediction using SNARIMAX
- AttackSequenceTracker: Pattern-based attack prediction
- FeatureExtractor: Network feature extraction (legacy compatible)

Legacy components (TensorFlow-based) archived in: ml/legacy_tensorflow/
"""

from .river_engine import RiverMLEngine
from .inference_engine import InferenceEngine
from .smart_recommender import SmartRecommender
from .traffic_forecaster import TrafficForecaster
from .attack_sequence_tracker import AttackSequenceTracker
from .feature_extractor import FeatureExtractor

__all__ = [
    'RiverMLEngine',
    'InferenceEngine',
    'SmartRecommender',
    'TrafficForecaster',
    'AttackSequenceTracker',
    'FeatureExtractor',
]
