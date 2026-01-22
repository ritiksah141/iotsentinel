#!/bin/bash
##############################################################################
# IoTSentinel Test Runner Script
#
# Automated test execution with multiple modes for different scenarios:
# - Quick: Fast tests only (for development)
# - Full: All tests with coverage (for CI/CD)
# - Critical: Must-pass tests only (for deployment checks)
# - Report: Generate detailed coverage report
#
# Usage:
#   ./run_tests.sh                 # Run all tests
#   ./run_tests.sh quick           # Run quick tests only
#   ./run_tests.sh critical        # Run critical tests only
#   ./run_tests.sh report          # Generate HTML coverage report
#   ./run_tests.sh help            # Show help
##############################################################################

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root directory (parent of scripts folder)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   IoTSentinel Test Suite Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to show help
show_help() {
    echo "Usage: ./run_tests.sh [MODE]"
    echo ""
    echo "Modes:"
    echo "  quick      - Run fast tests only (excludes slow, API tests)"
    echo "  full       - Run all tests with coverage (default)"
    echo "  critical   - Run critical tests only (for deployment)"
    echo "  unit       - Run unit tests only"
    echo "  integration - Run integration tests only"
    echo "  dashboard  - Run dashboard feature tests only"
    echo "  api        - Run API integration tests only"
    echo "  pi         - Run Pi integration tests (deployment validation)"
    echo "  report     - Generate HTML coverage report and open it"
    echo "  help       - Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./run_tests.sh                 # Run all tests"
    echo "  ./run_tests.sh quick           # Development mode"
    echo "  ./run_tests.sh critical        # Pre-deployment check"
    echo "  ./run_tests.sh pi              # Validate Pi deployment"
    echo "  ./run_tests.sh report          # Generate coverage report"
    echo ""
}

# Check if pytest is installed
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"

    if ! command -v pytest &> /dev/null; then
        echo -e "${RED}❌ pytest not found!${NC}"
        echo "Install with: pip install pytest pytest-cov pytest-mock"
        exit 1
    fi

    echo -e "${GREEN}✓ pytest found${NC}"

    # Check if .env file exists
    if [ ! -f ".env" ]; then
        echo -e "${YELLOW}⚠️  .env file not found - API tests may be skipped${NC}"
    else
        echo -e "${GREEN}✓ .env file found${NC}"
    fi

    echo ""
}

# Load environment variables from .env
load_env() {
    if [ -f ".env" ]; then
        echo -e "${YELLOW}Loading .env file...${NC}"
        set -a
        source .env
        set +a
        echo -e "${GREEN}✓ Environment variables loaded${NC}"
        echo ""
    fi
}

# Run tests based on mode
run_tests() {
    local mode="${1:-full}"

    case "$mode" in
        quick)
            echo -e "${BLUE}Running quick tests (excludes slow & API tests)...${NC}"
            pytest -v -m "not slow and not api" \
                --tb=short \
                --cov=. \
                --cov-report=term-missing:skip-covered
            ;;

        full)
            echo -e "${BLUE}Running full test suite with coverage...${NC}"
            pytest -v \
                --tb=short \
                --cov=. \
                --cov-report=html:htmlcov \
                --cov-report=term-missing:skip-covered
            ;;

        critical)
            echo -e "${BLUE}Running critical tests only...${NC}"
            pytest -v -m critical \
                --tb=short \
                --cov=. \
                --cov-report=term-missing:skip-covered \
                --cov-fail-under=80
            ;;

        unit)
            echo -e "${BLUE}Running unit tests only...${NC}"
            pytest -v -m unit \
                --tb=short \
                --cov=. \
                --cov-report=term-missing:skip-covered
            ;;

        integration)
            echo -e "${BLUE}Running integration tests only...${NC}"
            pytest -v -m integration \
                --tb=short \
                --cov=. \
                --cov-report=term-missing:skip-covered
            ;;

        dashboard)
            echo -e "${BLUE}Running dashboard feature tests...${NC}"
            pytest -v -m dashboard \
                tests/test_dashboard_features.py \
                --tb=short
            ;;

        api)
            echo -e "${BLUE}Running API integration tests...${NC}"
            pytest -v -m api \
                tests/test_dashboard_api_integration.py \
                --tb=short
            ;;

        pi)
            echo -e "${BLUE}Running Pi integration tests...${NC}"
            echo -e "${YELLOW}Note: These verify Pi deployment readiness${NC}"
            pytest -v "${PROJECT_ROOT}/tests/test_pi_integration.py" \
                --tb=short
            ;;

        report)
            echo -e "${BLUE}Generating HTML coverage report...${NC}"
            pytest --cov=. \
                --cov-report=html:htmlcov \
                --cov-report=term

            echo ""
            echo -e "${GREEN}✓ Coverage report generated!${NC}"
            echo -e "  Location: ${BLUE}htmlcov/index.html${NC}"
            echo ""

            # Try to open the report
            if command -v open &> /dev/null; then
                echo -e "${YELLOW}Opening report in browser...${NC}"
                open htmlcov/index.html
            elif command -v xdg-open &> /dev/null; then
                echo -e "${YELLOW}Opening report in browser...${NC}"
                xdg-open htmlcov/index.html
            else
                echo -e "${YELLOW}Please open htmlcov/index.html manually${NC}"
            fi
            return 0
            ;;

        help)
            show_help
            return 0
            ;;

        *)
            echo -e "${RED}Unknown mode: $mode${NC}"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Show test summary
show_summary() {
    local exit_code=$1

    echo ""
    echo -e "${BLUE}========================================${NC}"
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
    else
        echo -e "${RED}✗ Some tests failed${NC}"
    fi
    echo -e "${BLUE}========================================${NC}"
    echo ""

    # Show coverage summary if htmlcov exists
    if [ -d "htmlcov" ]; then
        echo -e "${YELLOW}Coverage report: htmlcov/index.html${NC}"
    fi

    # Show test documentation
    echo -e "${YELLOW}Test documentation: tests/README.md${NC}"
    echo ""
}

# Main execution
main() {
    local mode="${1:-full}"

    # Show help if requested
    if [ "$mode" == "help" ] || [ "$mode" == "-h" ] || [ "$mode" == "--help" ]; then
        show_help
        exit 0
    fi

    # Check dependencies
    check_dependencies

    # Load environment variables
    load_env

    # Run tests
    run_tests "$mode"
    local exit_code=$?

    # Show summary
    show_summary $exit_code

    exit $exit_code
}

# Run main function
main "$@"
