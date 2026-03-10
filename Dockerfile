# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────────
# libmagic  → python-magic (real MIME detection)
# libgl1    → OpenCV used internally by NudeNet
# libglib2.0-0 → also needed by OpenCV
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────────────────
WORKDIR /app

# ── Install Python deps first (layer cache) ───────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy app code ──────────────────────────────────────────────────────────────
COPY . .

# ── Railway injects $PORT at runtime — uvicorn reads it ───────────────────────
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}
