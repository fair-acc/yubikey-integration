# Yubikey Integration for Certificate/SSH Deployment
This repository provides some C++ tools to integrate the YubiKey PIV for secure key generation, encryption, and retrieval 
of sensitive assets (e.g. SSH keys, certificates). 
Physical access to the key is presumed secure, so the primary threat model targets unauthorised remote access.

## 1. Generate key (requires 'yubikey-manager' packager on admin/config machine):

```bash
ykman piv keys generate --algorithm RSA2048 --pin-policy NEVER --touch-policy NEVER --management-key 010203040506070801020304050607080102030405060708 9a yk_public.pem
```

This:
 * Generates a new RSA2048 key in slot 9C.
 * Saves the public key to yk_public.pem.
 * Ensures that no PIN or touch is required.

```bash
ykman piv keys info 9a
```
Typical output:
```text
Key slot:               9A (AUTHENTICATION)
Algorithm:              RSA2048
Origin:                 GENERATED
PIN required for use:   NEVER
Touch required for use: NEVER
```

See the [Yubico PIV Tool docs](https://developers.yubico.com/yubico-piv-tool/Actions/key_generation.html) for more details.

## 2. Retrieving the YubiKey Serial Number & Storing a Custom ID

The `yk_serial` tool can be used read the device’s **serial number**, **version**, and optionally **store/retrieve** a 
small custom identifier in the PIV data object `0x5FC106` (e.g. device- or hostname).

**Usage**:
```
./yk_serial -w <content>   # Write <content> to 0x5FC106 (requires management key)
./yk_serial -r             # Read only the custom object from 0x5FC106
./yk_serial -s             # Print only the YubiKey serial number
./yk_serial -a             # Print everything (serial, version, custom object)
```

**Examples**:

- Basic (verbose) output:
  ```bash
  ./yk_serial -a
  ``` 
  ```
  YubiKey Serial Number: 12345678
  YubiKey Version: 5.7.1
  Custom object (0x5FC106): 'hostname'
  ```

- Return only the serial number:
  ```bash
  ./yk_serial -s
  ```
  ```
  12345678
  ```

- read only custom object:
  ```bash
  ./yk_serial -r
  ```
  If set, it prints your stored text. If empty, a warning is shown.

- Write a new custom ID:
  ```bash
  ./yk_serial -w "My Device #37"
  ``` 

## 3. Inspecting the Public Key

The `inspect` tool shows the modulus (`n`), exponent (`e`), and key size:

```bash
./inspect yk_public.pem
```

Example output:

```bash
Modulus (n): C88F6D0A...
Exponent (e): 010001
RSA key size: 2048 bits (256 bytes)
```

## 4. Encrypting Secrets (`yk_encrypt`)

The `yk_encrypt` tool encrypts any binary or text file (e.g. an SSH private key):

```bash
./yk_encrypt <plaintext_input> yk_public.pem <encrypted_output>
```

- **`<plaintext_input>`**: the file you want to protect (e.g. `id_rsa`).
- **`yk_public.pem`**: the public RSA key from your YubiKey.
- **`<encrypted_output>`**: the ciphertext file to store in your git repo.

This produces a file that **can only be decrypted** with the YubiKey that holds the matching private key.

## 5. Decrypting Secrets (`yk_decrypt`)

To descrypt/recover the original file, you must have the configured YubiKey inserted:

```bash
./yk_decrypt <encrypted_input> <decrypted_output>
```

- **`<encrypted_input>`**: the file produced by `yk_encrypt`.
- **`<decrypted_output>`**: your restored original file.

If the YubiKey is present, `yk_decrypt` requests the YubiKey to perform the RSA operation. The AES key (which encrypted your data) is recovered, and the tool then decrypts the final ciphertext.
