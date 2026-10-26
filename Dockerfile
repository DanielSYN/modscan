FROM python:3.13-slim

RUN useradd --create-home scanner
WORKDIR /srv
COPY pyproject.toml README.md ./
COPY modscan modscan
RUN pip install --no-cache-dir .

# Uploaded files are hostile by assumption: run as an unprivileged user with nothing to protect.
USER scanner
EXPOSE 8000
CMD ["uvicorn", "modscan.web.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
