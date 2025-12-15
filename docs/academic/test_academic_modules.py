"""
Test Script for Academic Evidence Modules
Run this to verify all modules are working correctly
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from docs.academic.bcs_compliance import BCSComplianceManager
from docs.academic.rtm_generator import RTMGenerator
from docs.academic.risk_register import RiskRegisterManager
from docs.academic.performance_metrics import PerformanceMetricsCollector
from docs.academic.c4_generator import C4DiagramGenerator

# Use test database or real database
DB_PATH = project_root / "data" / "iotsentinel.db"

def test_bcs_compliance():
    """Test BCS Compliance Manager"""
    print("\n" + "="*60)
    print("Testing BCS Compliance Manager")
    print("="*60)

    try:
        bcs = BCSComplianceManager(str(DB_PATH))
        data = bcs.get_compliance_data()

        print(f"✓ BCS data collected successfully")
        print(f"  - Substantial Technical Challenge: {len(data['substantial_technical_challenge']['evidence'])} evidence items")
        print(f"  - Integration of Learning: {len(data['integration_of_learning']['modules_applied'])} modules")
        print(f"  - Professional Practice: {len(data['professional_practice']['practices'])} practices")
        print(f"  - Real-World Applicability: Raspberry Pi deployment ready")

        # Test export
        json_path = bcs.export_to_json()
        print(f"✓ Exported to: {json_path}")

        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def test_rtm_generator():
    """Test RTM Generator"""
    print("\n" + "="*60)
    print("Testing Requirements Traceability Matrix Generator")
    print("="*60)

    try:
        rtm = RTMGenerator(str(DB_PATH))
        data = rtm.get_rtm_data()
        stats = rtm.get_summary_statistics()
        coverage = rtm.get_coverage_by_epic()

        print(f"✓ RTM data collected successfully")
        print(f"  - Total Epics: {stats['total_epics']}")
        print(f"  - Total User Stories: {stats['total_user_stories']}")
        print(f"  - Total Tests: {stats['total_tests']}")
        print(f"  - Average Coverage: {stats['average_coverage']}%")
        print(f"  - Completion: {stats['completion_percentage']}%")

        # Test export
        csv_path = rtm.export_to_csv()
        print(f"✓ Exported to: {csv_path}")

        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def test_risk_register():
    """Test Risk Register Manager"""
    print("\n" + "="*60)
    print("Testing Risk Register Manager")
    print("="*60)

    try:
        risk_mgr = RiskRegisterManager(str(DB_PATH))
        risks = risk_mgr.get_risk_register()
        summary = risk_mgr.get_risk_summary()

        print(f"✓ Risk register loaded successfully")
        print(f"  - Total Risks: {summary['total_risks']}")
        print(f"  - Critical: {summary['by_severity']['CRITICAL']}")
        print(f"  - High: {summary['by_severity']['HIGH']}")
        print(f"  - Medium: {summary['by_severity']['MEDIUM']}")
        print(f"  - Mitigation Rate: {summary['mitigation_rate']}%")

        # Show first risk
        if risks:
            risk = risks[0]
            print(f"\n  Example Risk: {risk['risk_id']} - {risk['title']}")
            print(f"    Status: {risk['current_status']}")
            print(f"    Mitigation Stages: {len(risk['mitigation_stages'])}")

        # Test export
        json_path = risk_mgr.export_to_json()
        print(f"✓ Exported to: {json_path}")

        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def test_performance_metrics():
    """Test Performance Metrics Collector"""
    print("\n" + "="*60)
    print("Testing Performance Metrics Collector")
    print("="*60)

    try:
        perf = PerformanceMetricsCollector(str(DB_PATH))

        # Collect current metrics
        metrics = perf.collect_metrics()
        print(f"✓ Metrics collected successfully")
        print(f"  - CPU Usage: {metrics['cpu_usage']}%")
        print(f"  - RAM Usage: {metrics['ram_usage_percent']}% ({metrics['ram_usage_mb']:.0f} MB)")
        print(f"  - Disk Usage: {metrics['disk_usage_percent']}%")
        print(f"  - Packet Rate: {metrics['packet_processing_rate']} pps (estimated)")
        print(f"  - ML Latency: {metrics['ml_inference_latency_ms']} ms")

        # Store metrics
        perf.store_metrics(metrics)
        print(f"✓ Metrics stored to database")

        # Get summary
        summary = perf.get_performance_summary()
        print(f"✓ Performance summary generated")
        print(f"  - Samples: {summary['total_samples']}")
        print(f"  - CPU Status: {summary['cpu']['status']}")
        print(f"  - Memory Status: {summary['memory']['status']}")

        # Test benchmark comparison
        benchmarks = perf.get_benchmark_comparison()
        print(f"✓ Benchmarks available: Pcap+dpkt vs PyShark")

        # Test export
        csv_path = perf.export_to_csv()
        print(f"✓ Exported to: {csv_path}")

        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_c4_generator():
    """Test C4 Diagram Generator"""
    print("\n" + "="*60)
    print("Testing C4 Architecture Diagram Generator")
    print("="*60)

    try:
        c4 = C4DiagramGenerator(str(DB_PATH))

        # Get architecture description
        arch = c4.get_architecture_description()
        print(f"✓ Architecture description loaded")
        print(f"  - System: {arch['system_overview']['name']}")
        print(f"  - Deployment: {arch['system_overview']['deployment']}")
        print(f"  - Layers: {len(arch['layers'])}")
        print(f"  - Design Patterns: {len(arch['design_patterns'])}")
        print(f"  - Technology Decisions: {len(arch['technology_decisions'])}")

        # List layers
        print("\n  Architecture Layers:")
        for layer in arch['layers']:
            print(f"    - {layer['layer']}: {len(layer['components'])} components")

        # Test diagram generation
        print("\n  Generating C4 diagrams...")
        try:
            diagrams = c4.generate_all_diagrams()
            print(f"✓ Diagrams generated:")
            for name, path in diagrams.items():
                print(f"    - {name}: {path}")
        except ImportError:
            print(f"⚠ Warning: 'diagrams' library not installed, text-based diagrams generated")
            diagrams = c4._generate_text_based_diagrams()
            for name, path in diagrams.items():
                print(f"    - {name} (text): {path}")

        # Test export
        json_path = c4.export_architecture_docs()
        print(f"✓ Architecture docs exported to: {json_path}")

        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("ACADEMIC EVIDENCE MODULES - COMPREHENSIVE TEST")
    print("="*60)
    print(f"Database: {DB_PATH}")
    print(f"Database exists: {DB_PATH.exists()}")

    results = {
        "BCS Compliance": test_bcs_compliance(),
        "RTM Generator": test_rtm_generator(),
        "Risk Register": test_risk_register(),
        "Performance Metrics": test_performance_metrics(),
        "C4 Diagram Generator": test_c4_generator()
    }

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for module, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} - {module}")

    print(f"\nOverall: {passed}/{total} modules passed")

    if passed == total:
        print("\n🎉 All academic evidence modules working correctly!")
        print("\nNext steps:")
        print("1. Review ACADEMIC_EVIDENCE_INTEGRATION_GUIDE.md")
        print("2. Integrate into dashboard/app.py")
        print("3. Install dependencies: pip install diagrams psutil")
        print("4. Test dashboard integration")
        return 0
    else:
        print("\n⚠ Some modules failed. Please check errors above.")
        return 1


if __name__ == "__main__":
    exit(main())
