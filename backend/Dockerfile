FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# CPU-only PyTorch first: the default PyPI wheel bundles ~2 GB of CUDA libraries
# that a CPU host never uses. requirements.txt's torch>=2.2 is then already satisfied.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DATABASE_URL=sqlite:////app/phishscan.db
ENV CORS_ORIGINS=http://localhost:3000
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Hosts like Render/Railway/Fly inject $PORT; fall back to 8000 locally.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
