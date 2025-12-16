#!/bin/bash

# C4 Diagram Generator for IoTSentinel
# Generates PNG diagrams from mermaid files using mermaid-cli (mmdc)

set -e  # Exit on error

echo "🎨 IoTSentinel C4 Diagram Generator"
echo "===================================="
echo ""

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIAGRAMS_DIR="$SCRIPT_DIR/diagrams"
IMAGES_DIR="$SCRIPT_DIR/images"

echo "📁 Directories:"
echo "   Source: $DIAGRAMS_DIR"
echo "   Output: $IMAGES_DIR"
echo ""

# Check if mermaid-cli is installed
if ! command -v mmdc &> /dev/null; then
    echo -e "${RED}❌ Error: mermaid-cli (mmdc) not found${NC}"
    echo ""
    echo "Please install it first:"
    echo ""
    echo "  npm install -g @mermaid-js/mermaid-cli"
    echo ""
    echo "Or using Homebrew (macOS):"
    echo "  brew install mermaid-cli"
    echo ""
    exit 1
fi

echo -e "${GREEN}✅ mermaid-cli found${NC}"
mmdc --version
echo ""

# Create images directory if it doesn't exist
mkdir -p "$IMAGES_DIR"

# Configuration for diagram generation
CONFIG_FILE="$DIAGRAMS_DIR/mermaid-config-improved.json"

# Check if improved config exists, if not create it
if [ ! -f "$CONFIG_FILE" ]; then
cat > "$CONFIG_FILE" << 'EOF'
{
  "theme": "base",
  "themeVariables": {
    "primaryColor": "#4A90E2",
    "primaryTextColor": "#FFFFFF",
    "primaryBorderColor": "#2E5C8A",
    "lineColor": "#6B7280",
    "secondaryColor": "#10B981",
    "secondaryTextColor": "#FFFFFF",
    "tertiaryColor": "#F59E0B",
    "tertiaryTextColor": "#FFFFFF",
    "fontSize": "18px",
    "fontFamily": "arial, helvetica, sans-serif"
  },
  "flowchart": {
    "curve": "basis",
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 100,
    "rankSpacing": 100,
    "padding": 20
  }
}
EOF
fi

echo "🔄 Generating diagrams..."
echo ""

# Define diagram mappings (input -> output)
DIAGRAM_1_IN="level1_system_context.mmd"
DIAGRAM_1_OUT="c4_level1_system_context.png"

DIAGRAM_2_IN="level2_containers.mmd"
DIAGRAM_2_OUT="c4_level2_containers.png"

DIAGRAM_3_IN="level3_components.mmd"
DIAGRAM_3_OUT="c4_level3_components.png"

DIAGRAM_4_IN="level4_classes.mmd"
DIAGRAM_4_OUT="c4_level4_classes.png"

# Counter for progress
TOTAL=4
CURRENT=0
SUCCESS_COUNT=0

# Function to generate a diagram
generate_diagram() {
    local input_file="$1"
    local output_file="$2"
    local diagram_num="$3"

    local input_path="$DIAGRAMS_DIR/$input_file"
    local output_path="$IMAGES_DIR/$output_file"

    if [ ! -f "$input_path" ]; then
        echo -e "${RED}❌ [$diagram_num/$TOTAL] Error: $input_file not found${NC}"
        return 1
    fi

    echo -e "${BLUE}[$diagram_num/$TOTAL]${NC} Generating: $output_file"

    # Generate PNG with high quality settings (larger size for better readability)
    if mmdc -i "$input_path" -o "$output_path" -c "$CONFIG_FILE" -b white -w 2400 -H 1600 -s 2 2>/dev/null; then
        FILE_SIZE=$(ls -lh "$output_path" | awk '{print $5}')
        echo -e "       ${GREEN}✓${NC} Generated successfully ($FILE_SIZE)"
        return 0
    else
        echo -e "       ${RED}✗${NC} Failed to generate"
        return 1
    fi
}

# Generate each diagram
generate_diagram "$DIAGRAM_1_IN" "$DIAGRAM_1_OUT" 1 && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
echo ""
generate_diagram "$DIAGRAM_2_IN" "$DIAGRAM_2_OUT" 2 && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
echo ""
generate_diagram "$DIAGRAM_3_IN" "$DIAGRAM_3_OUT" 3 && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
echo ""
generate_diagram "$DIAGRAM_4_IN" "$DIAGRAM_4_OUT" 4 && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
echo ""

# Summary
echo "📊 Generation Summary"
echo "===================="
echo ""

if [ "$SUCCESS_COUNT" -eq "$TOTAL" ]; then
    echo -e "${GREEN}✅ All $TOTAL diagrams generated successfully!${NC}"
elif [ "$SUCCESS_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Generated $SUCCESS_COUNT out of $TOTAL diagrams${NC}"
else
    echo -e "${RED}❌ Failed to generate diagrams${NC}"
    exit 1
fi

echo ""
echo "📍 Output location: $IMAGES_DIR"
echo ""

if [ "$SUCCESS_COUNT" -gt 0 ]; then
    echo "Generated files:"
    ls -lh "$IMAGES_DIR"/c4_*.png 2>/dev/null | awk '{print "   " $9 " (" $5 ")"}'
    echo ""
fi

# Check for old images
if ls "$IMAGES_DIR"/image*.png 1> /dev/null 2>&1; then
    echo "🧹 Clean up old images:"
    echo "   cd $IMAGES_DIR"
    ls -1 "$IMAGES_DIR"/image*.png | while read img; do
        echo "   rm $(basename "$img")"
    done
    echo ""
fi

echo -e "${GREEN}✅ Done!${NC}"
