#!/bin/bash

TARGET="https://bugbase.ai"
OUTPUT_DIR="./bugbase_chunks"
MANIFEST_CHUNK="webpack-9b98297ce5cfdf8c.js"

mkdir -p "$OUTPUT_DIR"

echo "[+] Extracting chunk mappings from manifest"
curl -s "${TARGET}/_next/static/chunks/${MANIFEST_CHUNK}" | grep -oE '[0-9]{4}:"[a-f0-9]{16}"' | while read -r line; do
    CHUNK_ID=$(echo "$line" | cut -d':' -f1)
    CHUNK_HASH=$(echo "$line" | cut -d'"' -f2)
    FILENAME="${CHUNK_ID}.${CHUNK_HASH}.js"
    
    echo "[+] Downloading chunk: $FILENAME"
    curl -s "${TARGET}/_next/static/chunks/${FILENAME}" -o "${OUTPUT_DIR}/${FILENAME}"
done

echo "[+] Searching for API endpoints across all chunks"
grep -rhoE '(/api/|/v1/|/v2/)[a-zA-Z0-9_./-]*' "$OUTPUT_DIR" | sort -u

echo "[+] Searching for page routes across all chunks"
grep -rhoE 'app/[a-zA-Z0-9_%5B%5D/_-]+' "$OUTPUT_DIR" | sort -u

echo "[+] Searching for potential configuration leaks"
grep -rhiE '(key|secret|token|auth|config|credential)\s*[:=]\s*["\x27][^"\x27]{10,}["\x27]' "$OUTPUT_DIR" | sort -u

echo "[+] Searching for internal endpoints"
grep -rhiE '(https?://)[a-zA-Z0-9.-]+/[a-zA-Z0-9_/-]+' "$OUTPUT_DIR" | grep -v "$TARGET" | sort -u
