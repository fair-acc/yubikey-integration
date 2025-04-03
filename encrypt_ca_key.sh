#!/bin/bash
# encrypt_ca_key.sh - One-time encryption of the CA-issued private key
#
# Usage:
#   ./encrypt_ca_key.sh <CA_key_file> <yk_public_key_file> <output_file>
#
# This script performs hybrid encryption:
#  1. Generates a random 256-bit AES key and a 128-bit IV.
#  2. Encrypts the CA-issued key with AES-256-CBC.
#  3. Encrypts the AES key with the YubiKey’s RSA public key.
#  4. Combines the RSA-encrypted AES key, the IV, and the AES ciphertext into one file.
#
# Note: In production, consider using AES-256-GCM for authenticated encryption.

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <CA_key_file> <yk_public_key_file> <output_file>"
    exit 1
fi

CA_KEY_FILE="$1"
YK_PUBLIC_KEY_FILE="$2"
OUTPUT_FILE="$3"

# 1. Generate a random AES key (256-bit) and IV (128-bit)
openssl rand -out aes_key.bin 32
openssl rand -out aes_iv.bin 16

# Convert binary key and IV to hex string without newlines:
AES_KEY_HEX=$(xxd -p aes_key.bin | tr -d '\n')
AES_IV_HEX=$(xxd -p aes_iv.bin | tr -d '\n')

# Debug prints (optional)
# echo "AES Key: $AES_KEY_HEX"
# echo "AES IV:  $AES_IV_HEX"

# 2. Encrypt the CA-issued private key using AES-256-CBC.
openssl enc -aes-256-cbc -in "$CA_KEY_FILE" -out ca_key.enc -K "$AES_KEY_HEX" -iv "$AES_IV_HEX"

# 3. Encrypt the AES key with the YubiKey's RSA public key (PKCS#1 padding)
openssl rsautl -encrypt -inkey "$YK_PUBLIC_KEY_FILE" -pubin -in aes_key.bin -out aes_key.enc

# 4. Package the components into a single output file.
# Format: [4 bytes: length of RSA-encrypted AES key][encrypted AES key][16 bytes IV][AES ciphertext]
AES_KEY_ENC_SIZE=$(stat -c%s aes_key.enc)
printf "%04x" $AES_KEY_ENC_SIZE | xxd -r -p > "$OUTPUT_FILE"
cat aes_key.enc >> "$OUTPUT_FILE"
cat aes_iv.bin >> "$OUTPUT_FILE"
cat ca_key.enc >> "$OUTPUT_FILE"

# Clean up temporary files
rm aes_key.bin aes_iv.bin aes_key.enc ca_key.enc

echo "Encryption complete. Output written to $OUTPUT_FILE"
