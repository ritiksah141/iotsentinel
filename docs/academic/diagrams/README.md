# C4 Architecture Diagrams

This folder contains the source mermaid files (.mmd) for all C4 architecture diagrams.

## 📁 Files

- `level1_system_context.mmd` - System Context (Level 1)
- `level2_containers.mmd` - Container Diagram (Level 2)
- `level3_components.mmd` - Component Diagram (Level 3)
- `level4_classes.mmd` - Class Diagram (Level 4)

## 🔄 Generating PNG Diagrams

### Automatic (Recommended)

Run the generation script from the `docs/academic/` directory:

```bash
cd docs/academic
./generate_diagrams.sh
```

The script will:
- ✅ Check for mermaid-cli installation
- ✅ Generate all 4 PNG diagrams
- ✅ Save to `docs/academic/images/` with proper names
- ✅ Show progress and file sizes

### Manual (Using mermaid.live)

1. Go to https://mermaid.live/
2. Copy content from any `.mmd` file
3. Paste into the editor
4. Click "Actions" → "Download PNG"
5. Save to `../images/` with the corresponding name

## 📦 Installation (if needed)

If you don't have mermaid-cli installed:

```bash
# Using npm
npm install -g @mermaid-js/mermaid-cli

# Using Homebrew (macOS)
brew install mermaid-cli

# Verify installation
mmdc --version
```

## 📝 Diagram Mapping

| Source File | Output PNG | Description |
|-------------|------------|-------------|
| `level1_system_context.mmd` | `c4_level1_system_context.png` | High-level system context |
| `level2_containers.mmd` | `c4_level2_containers.png` | Container architecture |
| `level3_components.mmd` | `c4_level3_components.png` | Component details |
| `level4_classes.mmd` | `c4_level4_classes.png` | Class relationships |

## 🎨 Customization

To modify diagrams:
1. Edit the `.mmd` files in this directory
2. Run `../generate_diagrams.sh` to regenerate PNGs
3. The updated images will be automatically used in `C4_ARCHITECTURE.md`

## 📍 Output Location

Generated PNG files are saved to: `docs/academic/images/`

These are referenced in: `docs/academic/C4_ARCHITECTURE.md`

---

**Last Updated**: December 2025
**Mermaid Version**: Compatible with mermaid-cli 10.0+
