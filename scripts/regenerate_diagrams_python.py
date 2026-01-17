#!/usr/bin/env python3
"""
Regenerate Architecture Diagrams using Mermaid Ink API

This script converts Mermaid .mmd files to PNG images using the free
mermaid.ink API service. No local installation required!

Usage:
    python3 scripts/regenerate_diagrams_python.py
"""

import os
import urllib.request
import urllib.parse
import base64
import json
from pathlib import Path

# Color codes for terminal output
GREEN = '\033[0;32m'
BLUE = '\033[0;34m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
NC = '\033[0m'

def print_color(color, text):
    """Print colored text to terminal"""
    print(f"{color}{text}{NC}")

def encode_mermaid(mmd_content):
    """Encode Mermaid diagram content for URL"""
    # Remove comments and clean up
    lines = [line for line in mmd_content.split('\n') if not line.strip().startswith('%%')]
    cleaned = '\n'.join(lines)

    # Base64 encode
    encoded = base64.urlsafe_b64encode(cleaned.encode('utf-8')).decode('utf-8')
    return encoded

def generate_diagram(input_file, output_file):
    """Generate PNG diagram from Mermaid file using mermaid.ink API"""

    print_color(BLUE, f"  📄 Reading {input_file.name}...")

    # Read mermaid file
    with open(input_file, 'r') as f:
        mmd_content = f.read()

    # Encode for URL
    encoded = encode_mermaid(mmd_content)

    # Construct mermaid.ink URL
    # Using PNG format with white background
    url = f"https://mermaid.ink/img/{encoded}"

    print_color(BLUE, f"  🌐 Fetching from mermaid.ink...")

    try:
        # Download PNG
        with urllib.request.urlopen(url, timeout=30) as response:
            img_data = response.read()

        # Save to file
        with open(output_file, 'wb') as f:
            f.write(img_data)

        size = len(img_data) / 1024  # KB
        print_color(GREEN, f"  ✅ Generated {output_file.name} ({size:.1f} KB)")
        return True

    except Exception as e:
        print_color(RED, f"  ❌ Failed: {e}")
        return False

def main():
    """Main function to regenerate all diagrams"""

    print("🎨 Regenerating IoTSentinel Architecture Diagrams (River ML)")
    print("=" * 65)
    print()

    # Get project directories
    project_root = Path(__file__).parent.parent
    diagrams_dir = project_root / "docs" / "academic" / "diagrams"
    images_dir = project_root / "docs" / "academic" / "images"

    print(f"📁 Directories:")
    print(f"   Source: {diagrams_dir}")
    print(f"   Output: {images_dir}")
    print()

    # Create output directory
    images_dir.mkdir(parents=True, exist_ok=True)

    # Diagram mappings
    diagrams = {
        "level1_system_context.mmd": "c4_level1_system_context.png",
        "level2_containers.mmd": "c4_level2_containers.png",
        "level3_components.mmd": "c4_level3_components.png",
        "level4_classes.mmd": "c4_level4_classes.png"
    }

    print("🔄 Generating PNG diagrams using mermaid.ink API...")
    print()

    success_count = 0
    total = len(diagrams)

    for idx, (input_name, output_name) in enumerate(diagrams.items(), 1):
        print_color(BLUE, f"[{idx}/{total}] {output_name}")

        input_path = diagrams_dir / input_name
        output_path = images_dir / output_name

        if not input_path.exists():
            print_color(RED, f"  ❌ Source file not found: {input_name}")
            continue

        if generate_diagram(input_path, output_path):
            success_count += 1

        print()

    print()
    print_color(GREEN, f"✨ Generation complete! ({success_count}/{total} successful)")
    print()

    # List generated files
    print("📊 Generated files:")
    png_files = sorted(images_dir.glob("*.png"))
    for png_file in png_files:
        size = png_file.stat().st_size / 1024  # KB
        print(f"   {png_file.name} ({size:.1f} KB)")

    print()
    print("🎯 Updated diagrams now reflect River ML architecture:")
    print("   - HalfSpaceTrees (Anomaly Detection)")
    print("   - HoeffdingAdaptive (Attack Classification)")
    print("   - SNARIMAX (Traffic Forecasting)")
    print()

    if success_count < total:
        print_color(YELLOW, "⚠️  Some diagrams failed to generate. Check the errors above.")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
