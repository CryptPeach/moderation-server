# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────────
# gcc         → needed by some pip packages that compile C extensions
# libmagic1   → python-magic (real MIME type detection)
# libgl1      → OpenCV dependency
# libglib2.0-0 → OpenCV dependency
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────────────────
WORKDIR /app

# ── Install Python deps (cached layer — only rebuilds if requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy app code ──────────────────────────────────────────────────────────────
COPY . .

# ── Railway injects $PORT at runtime ─────────────────────────────────────────
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}
