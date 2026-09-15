# Using python:3.9-slim deliberately because it contains known CVEs in its OS packages
# This gives Trivy's container scanner something real to catch at the HIGH/CRITICAL level.
FROM python:3.12-alpine

# Set working directory
WORKDIR /app

# Copy requirements and install
# We copy this first to leverage Docker layer caching
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ .

# Run as non-root user (good practice, though image is still vulnerable)
RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
