#!/usr/bin/env python3
"""
Automatic Integration Script for Academic Evidence Dashboard

This script helps integrate the academic evidence features into your main dashboard.
It provides guided steps to add the necessary code to dashboard/app.py

Usage:
    python scripts/integrate_academic_evidence.py

Options:
    --dry-run : Show what would be changed without making modifications
    --help    : Show this help message
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def print_step(step_num, title):
    """Print a step header"""
    print(f"\n{'─'*70}")
    print(f"STEP {step_num}: {title}")
    print('─'*70)


def check_prerequisites():
    """Check if all required files exist"""
    print_header("Prerequisites Check")

    required_files = [
        "docs/academic/__init__.py",
        "docs/academic/bcs_compliance.py",
        "docs/academic/rtm_generator.py",
        "docs/academic/risk_register.py",
        "docs/academic/performance_metrics.py",
        "docs/academic/c4_generator.py",
        "docs/academic/dashboard_components.py",
        "dashboard/app.py"
    ]

    all_exist = True
    for file_path in required_files:
        full_path = project_root / file_path
        if full_path.exists():
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path} - NOT FOUND!")
            all_exist = False

    return all_exist


def check_dependencies():
    """Check if required Python packages are installed"""
    print_header("Dependency Check")

    dependencies = {
        "dash": "Dashboard framework",
        "dash_bootstrap_components": "Bootstrap components",
        "plotly": "Visualization library",
        "pandas": "Data manipulation",
        "psutil": "System metrics",
    }

    optional = {
        "diagrams": "C4 diagram generation (optional - has text fallback)"
    }

    print("Required packages:")
    all_installed = True
    for package, description in dependencies.items():
        try:
            __import__(package)
            print(f"✓ {package} - {description}")
        except ImportError:
            print(f"✗ {package} - NOT INSTALLED - {description}")
            all_installed = False

    print("\nOptional packages:")
    for package, description in optional.items():
        try:
            __import__(package)
            print(f"✓ {package} - {description}")
        except ImportError:
            print(f"⚠ {package} - NOT INSTALLED - {description}")

    if not all_installed:
        print("\n⚠ Install missing packages:")
        print("pip install -r requirements.txt")

    return all_installed


def show_integration_code():
    """Show the code that needs to be added to dashboard/app.py"""
    print_header("Integration Code")

    print("Add the following code to your dashboard/app.py:\n")

    print("─" * 70)
    print("SECTION 1: Imports (add after your existing imports)")
    print("─" * 70)
    print("""
# Academic Evidence Dashboard Integration
from docs.academic.dashboard_components import (
    create_academic_evidence_button,
    create_academic_modal,
    register_callbacks as register_academic_callbacks
)
""")

    print("─" * 70)
    print("SECTION 2: Button in Layout (add to navbar or header)")
    print("─" * 70)
    print("""
# Add this button somewhere visible (e.g., in your navbar)
create_academic_evidence_button(),
""")

    print("─" * 70)
    print("SECTION 3: Modal in Layout (add at the end of layout)")
    print("─" * 70)
    print("""
# Add this modal at the end of your layout
create_academic_modal(DB_PATH),
""")

    print("─" * 70)
    print("SECTION 4: Callbacks (add after app.layout definition)")
    print("─" * 70)
    print("""
# Register academic evidence callbacks (MUST be after app.layout)
register_academic_callbacks(app, DB_PATH)
""")


def test_integration():
    """Test if academic modules can be imported and work"""
    print_header("Testing Academic Modules")

    try:
        from docs.academic.dashboard_components import (
            create_academic_evidence_button,
            create_academic_modal,
            register_callbacks
        )
        print("✓ Successfully imported dashboard_components")

        from docs.academic.bcs_compliance import BCSComplianceManager
        from docs.academic.rtm_generator import RTMGenerator
        from docs.academic.risk_register import RiskRegisterManager
        from docs.academic.performance_metrics import PerformanceMetricsCollector
        from docs.academic.c4_generator import C4DiagramGenerator

        print("✓ Successfully imported all academic modules")

        # Quick test
        db_path = str(project_root / "data" / "iotsentinel.db")
        bcs = BCSComplianceManager(db_path)
        data = bcs.get_compliance_data()
        print(f"✓ BCS Compliance: {len(data['substantial_technical_challenge']['evidence'])} evidence items")

        rtm = RTMGenerator(db_path)
        stats = rtm.get_summary_statistics()
        print(f"✓ RTM: {stats['total_user_stories']} user stories documented")

        risks = RiskRegisterManager(db_path)
        summary = risks.get_risk_summary()
        print(f"✓ Risk Register: {summary['total_risks']} risks, {summary['mitigation_rate']}% mitigated")

        print("\n✅ All modules working correctly!")
        return True

    except Exception as e:
        print(f"\n✗ Error testing modules: {e}")
        import traceback
        traceback.print_exc()
        return False


def show_dashboard_snippet():
    """Show a complete example of integrated dashboard"""
    print_header("Complete Integration Example")

    print("Here's a minimal working example:\n")

    print("""
import dash
import dash_bootstrap_components as dbc
from dash import html
from pathlib import Path

# Your existing imports...
from config.config_manager import config
from database.db_manager import DatabaseManager

# ACADEMIC EVIDENCE IMPORTS
from docs.academic.dashboard_components import (
    create_academic_evidence_button,
    create_academic_modal,
    register_callbacks as register_academic_callbacks
)

# Initialize app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

# Database path
DB_PATH = config.get('database', 'path')

# Create layout
app.layout = html.Div([
    # Your navbar with academic button
    dbc.Navbar([
        dbc.Container([
            dbc.NavbarBrand("IoTSentinel"),
            dbc.Nav([
                create_academic_evidence_button(),  # ADD THIS
                # ... your other nav items ...
            ])
        ])
    ]),

    # Your main content...
    html.Div([
        html.H1("IoTSentinel Dashboard"),
        # ... your dashboard content ...
    ]),

    # Academic modal (at the end)
    create_academic_modal(DB_PATH),  # ADD THIS
])

# Register callbacks
# ... your existing callbacks ...

# REGISTER ACADEMIC CALLBACKS (must be after app.layout)
register_academic_callbacks(app, DB_PATH)  # ADD THIS

if __name__ == '__main__':
    app.run_server(debug=True)
""")


def show_next_steps():
    """Show next steps after integration"""
    print_header("Next Steps")

    print("After integrating the code:")
    print()
    print("1. Start your dashboard:")
    print("   $ python dashboard/app.py")
    print()
    print("2. Look for the 'Academic Evidence' button (graduation cap icon)")
    print()
    print("3. Click it to open the Academic Evidence modal")
    print()
    print("4. Navigate through all 6 tabs:")
    print("   - BCS Compliance")
    print("   - Requirements Traceability")
    print("   - Risk Register")
    print("   - Performance Metrics")
    print("   - Architecture (C4)")
    print("   - Export Evidence")
    print()
    print("5. Test export functionality in each tab")
    print()
    print("6. For submissions:")
    print("   - Take screenshots of each tab")
    print("   - Export all evidence (JSON/CSV)")
    print("   - Include in your AT2/AT3 reports")
    print()
    print("📚 For more details, see:")
    print("   - ACADEMIC_EVIDENCE_INTEGRATION_GUIDE.md")
    print("   - IMPLEMENTATION_COMPLETE.md")


def main():
    """Main integration script"""
    print("""
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║      IoTSentinel Academic Evidence Dashboard Integration          ║
║                                                                    ║
║  This script will guide you through integrating academic          ║
║  evidence features into your dashboard.                           ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
    """)

    # Check prerequisites
    print_step(1, "Checking Prerequisites")
    if not check_prerequisites():
        print("\n❌ Prerequisites check failed. Please ensure all files exist.")
        return 1

    # Check dependencies
    print_step(2, "Checking Dependencies")
    deps_ok = check_dependencies()
    if not deps_ok:
        print("\n⚠ Some dependencies are missing. Install them first.")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            return 1

    # Test modules
    print_step(3, "Testing Academic Modules")
    if not test_integration():
        print("\n❌ Module testing failed. Please check error messages.")
        return 1

    # Show integration code
    print_step(4, "Integration Code")
    show_integration_code()

    # Show complete example
    print_step(5, "Complete Example")
    show_dashboard_snippet()

    # Show next steps
    print_step(6, "Final Steps")
    show_next_steps()

    # Summary
    print_header("Summary")
    print("✅ Prerequisites: OK")
    print("✅ Dependencies: " + ("OK" if deps_ok else "⚠ Some missing (optional)"))
    print("✅ Module Tests: OK")
    print("✅ Integration Guide: Ready")
    print()
    print("🎉 You're ready to integrate academic evidence into your dashboard!")
    print()
    print("Copy the code from SECTION 1-4 above into your dashboard/app.py")
    print("Then run: python dashboard/app.py")
    print()
    print("For detailed instructions, see: ACADEMIC_EVIDENCE_INTEGRATION_GUIDE.md")

    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
