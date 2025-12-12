# 🤖 AI Chat Assistant Setup Guide

The IoTSentinel dashboard now includes an **AI-powered chat assistant** that can answer questions about your network security using a local LLM via Ollama.

---

## ✨ Features

- **100% Free & Private** - Runs locally on your network
- **Network-Aware** - Knows your current device count, active alerts, and recent security events
- **Automatic Fallback** - Uses rule-based responses if Ollama is unavailable
- **Easy Configuration** - Toggle AI mode on/off in `dashboard/app.py`

---

## 📦 Installation Options

### Option 1: Install on Raspberry Pi 5 (Recommended for small models)

```bash
# Install Ollama on your Pi
curl -fsSL https://ollama.com/install.sh | sh

# Pull a lightweight model (choose ONE)
ollama pull llama3.2:3b      # 3B params - Fast, good quality
ollama pull phi3:mini         # 3.8B params - Optimized for small devices
ollama pull gemma2:2b        # 2B params - Smallest option

# Start Ollama service (it should auto-start)
ollama serve
```

### Option 2: Install on a Separate Machine (Better performance)

If you have a laptop or desktop on the same network:

```bash
# On your laptop/desktop
curl -fsSL https://ollama.com/install.sh | sh

# Pull a more capable model
ollama pull llama3.2:3b      # Good balance
ollama pull mistral:7b       # More capable, slower
ollama pull llama3.1:8b      # Best quality, requires more RAM

# Start Ollama
ollama serve
```

Then update `dashboard/app.py` line 62 to point to your machine:
```python
OLLAMA_API_URL = "http://192.168.1.100:11434/api/generate"  # Use your machine's IP
```

---

## 🚀 Quick Start

### 1. Install Ollama
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### 2. Pull a Model
```bash
# Fastest (recommended for Pi 5)
ollama pull llama3.2:3b

# OR for better quality (if you have RAM)
ollama pull mistral:7b
```

### 3. Start the Service
```bash
# Ollama usually auto-starts, but you can manually run:
ollama serve
```

### 4. Verify Installation
```bash
# Test that Ollama is working
ollama run llama3.2:3b
>>> Hello!  # Type this and press Enter
# You should get a response from the model
# Press Ctrl+D to exit
```

### 5. Start IoTSentinel Dashboard
```bash
cd /path/to/iotsentinel
python3 dashboard/app.py
```

**Look for this in the startup logs:**
```
🤖 AI Chat: ✅ ENABLED (Ollama with llama3.2:3b)
```

---

## ⚙️ Configuration

Edit `dashboard/app.py` (lines 60-64):

```python
# AI Assistant Configuration
OLLAMA_ENABLED = True              # Set to False to disable AI completely
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"       # Change model here
OLLAMA_TIMEOUT = 30                # Seconds to wait for response
```

### Available Models

| Model | Size | Speed | Quality | Best For |
|-------|------|-------|---------|----------|
| `gemma2:2b` | 2B | ⚡⚡⚡⚡⚡ | ⭐⭐⭐ | Ultra-low resource |
| `llama3.2:3b` | 3B | ⚡⚡⚡⚡ | ⭐⭐⭐⭐ | **Pi 5 (Recommended)** |
| `phi3:mini` | 3.8B | ⚡⚡⚡⚡ | ⭐⭐⭐⭐ | Pi 5 alternative |
| `mistral:7b` | 7B | ⚡⚡⚡ | ⭐⭐⭐⭐⭐ | Separate machine |
| `llama3.1:8b` | 8B | ⚡⚡ | ⭐⭐⭐⭐⭐ | Best quality |

---

## 🔧 Troubleshooting

### AI Chat shows "⚠️ AI mode unavailable - using basic responses"

**Cause**: Ollama is not running or not accessible.

**Fix**:
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If it fails, start Ollama
ollama serve

# If it still doesn't work, check firewall
sudo systemctl status ollama
```

### Dashboard won't start with error about "requests"

**Cause**: Missing Python dependency.

**Fix**:
```bash
pip install requests
```

### Ollama is slow on Raspberry Pi 5

**Solutions**:
1. Use a smaller model: `ollama pull gemma2:2b`
2. Update model in `app.py`: `OLLAMA_MODEL = "gemma2:2b"`
3. OR run Ollama on a separate machine (see Option 2 above)

### Model download is taking forever

**Expected**: Models are large files (1-5GB). On Pi 5 with slow internet, it might take 10-30 minutes.

**Tip**: You can continue using the dashboard with rule-based responses while downloading.

---

## 🎯 Usage Examples

Once set up, open the dashboard and click the 🤖 robot icon to chat:

**Example Conversations**:

```
You: Is my network secure?
AI: Your network looks good with 8 active devices and no critical alerts.
    All devices are showing normal behavior patterns.

You: What is lockdown mode?
AI: Lockdown Mode blocks all untrusted devices from your network.
    It's useful during suspected security incidents. You can enable it
    in Settings → Firewall Control after marking trusted devices.

You: Tell me about the recent alert
AI: The most recent alert shows "High Outbound Traffic" on your Smart TV
    (192.168.1.50). This could indicate unusual data uploads. Check the
    device details for baseline comparisons.
```

---

## 💡 Tips

1. **First Response is Slower**: The first AI response after starting takes 5-10 seconds as the model loads into memory. Subsequent responses are much faster (1-3 seconds).

2. **Keep Ollama Running**: Set Ollama to auto-start on boot:
   ```bash
   # On Linux/Pi
   sudo systemctl enable ollama
   ```

3. **Disable AI if Needed**: Set `OLLAMA_ENABLED = False` in `app.py` to use only rule-based responses (instant, but less flexible).

4. **Monitor Resources**: Check RAM usage with `htop` while using AI chat. If your Pi struggles, switch to a smaller model.

---

## 🆓 Cost Comparison

| Solution | Setup Cost | Monthly Cost | Privacy |
|----------|------------|--------------|---------|
| **Ollama (This Setup)** | $0 | $0 | ⭐⭐⭐⭐⭐ (100% local) |
| Claude API | $0 | $1-5 | ⭐⭐ (cloud-based) |
| OpenAI GPT-3.5 | $0 | $0.50-2 | ⭐⭐ (cloud-based) |
| Rule-based (Fallback) | $0 | $0 | ⭐⭐⭐⭐⭐ (local) |

---

## 📚 Additional Resources

- **Ollama Documentation**: https://ollama.com/
- **Available Models**: https://ollama.com/library
- **Performance Tuning**: https://github.com/ollama/ollama/blob/main/docs/faq.md

---

## ❓ Need Help?

If you encounter issues:

1. Check the dashboard startup logs for AI status
2. Verify Ollama is running: `curl http://localhost:11434/api/tags`
3. Test the model directly: `ollama run llama3.2:3b`
4. Check logs: `journalctl -u ollama -f`

The AI chat will **always fall back to rule-based responses** if Ollama fails, so your dashboard will never break! 🛡️
