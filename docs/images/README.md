# README screenshots

Drop product screenshots / GIFs here with these exact filenames so the main
`README.md` references resolve:

| Filename | Screen |
|---|---|
| `dashboard-overview.png` | Frosted-glass overview: device cards, anomaly index, security score |
| `agent-timeline.png` | The 5-step transparent agent investigation timeline |
| `plain-english-alerts.png` | Rewritten plain-English alerts + the "Ask Why" AI analyst |
| `setup-wizard.png` | The 6-step browser setup wizard |
| `mobile-pwa.png` | (optional) Installed mobile / PWA view |

Recommended: 16:10 or 16:9, ~1600px wide, PNG for static shots and GIF for the
agent timeline / Ask Why interaction if you want motion.

**Keep each file under 500 KB** — the `check-added-large-files` pre-commit hook rejects
anything larger. UI screenshots compress well as palette PNGs (PNG-8); the committed shots
were ~580–775 KB as RGB and dropped to ~80 KB with no visible loss via:

```python
from PIL import Image
im = Image.open("shot.png").convert("RGB")
im.quantize(colors=256, method=Image.Quantize.LIBIMAGEQUANT).save("shot.png", optimize=True)
```
