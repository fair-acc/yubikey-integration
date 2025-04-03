#!/bin/bash
# boot_decrypt.sh - Retrieve config, decrypt CA-issued key, and start the server

set -euo pipefail

# 1. Retrieve machine unique ID from YubiKey (using ykman for example)
unique_id=$(ykman piv info | grep "Serial:" | awk '{print $2}')
echo "Machine Unique ID: $unique_id"

# 2. Fetch configuration based on unique_id (e.g. from a local file or via curl)
# For demonstration, assume a local config file named config_${unique_id}.json
# config_file="config_${unique_id}.json"
# if [ ! -f "$config_file" ]; then
#     echo "Error: Config file $config_file not found!"
#     exit 1
# fi
# echo "Loaded configuration from: $config_file"

# 3. Retrieve the encrypted CA-issued key (assumed to be stored in the config repo)
encrypted_key="encrypted_ca_key.bin"
if [ ! -f "$encrypted_key" ]; then
    echo "Error: Encrypted key file $encrypted_key not found!"
    exit 1
fi
echo "Encrypted key file located: $encrypted_key"

# 4. Decrypt the CA-issued key using the YubiKey.
# Assume we've compiled a tool named 'yk_decrypt' from our C++ example.
../yk_decrypt "$encrypted_key" "/tmp/secure_key"
if [ $? -ne 0 ]; then
    echo "Error: Decryption failed!"
    exit 1
fi
echo "Decrypted key stored at /tmp/secure_key"

# 5. Start the server using the decrypted key and the configuration.
# For example, the server binary might accept a key file and config file as arguments.
echo ./server --key /tmp/secure_key --config "$config_file"

