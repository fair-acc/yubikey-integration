#include <array>
#include <cstddef>
#include <cstdio>
#include <format>
#include <fstream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <optional>
#include <print>
#include <span>
#include <string_view>
#include <vector>

#include "yk_common.hpp"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::println("Usage: {} <plaintext_input> <rsa_public_key> <encrypted_output>", argv[0]);
        return 1;
    }

    auto plainOpt = readFile(argv[1]);
    if (!plainOpt || plainOpt->empty()) {
        std::println(stderr, "Error: Plaintext is empty or unreadable.");
        return 1;
    }
    auto& plaintext = *plainOpt;

    // generate random AES-256 key + 16-byte IV
    std::array<std::byte, 32> aesKey{};
    std::array<std::byte, 16> aesIV{};
    if (RAND_bytes(reinterpret_cast<unsigned char*>(aesKey.data()), aesKey.size()) != 1 || RAND_bytes(reinterpret_cast<unsigned char*>(aesIV.data()), aesIV.size()) != 1) {
        std::println(stderr, "Error: Failed to generate AES key/IV.");
        return 1;
    }

    // encrypt plaintext with AES-256-CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::println(stderr, "Error: EVP_CIPHER_CTX_new failed.");
        return 1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(aesKey.data()), reinterpret_cast<const unsigned char*>(aesIV.data())) != 1) {
        std::println(stderr, "Error: EVP_EncryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    std::vector<std::byte> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int                    outLen1 = 0;
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &outLen1, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1) {
        std::println(stderr, "Error: EVP_EncryptUpdate failed.");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int outLen2 = 0;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + outLen1, &outLen2) != 1) {
        std::println(stderr, "Error: EVP_EncryptFinal_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext.resize(outLen1 + outLen2);
    EVP_CIPHER_CTX_free(ctx);

    // load RSA public key into an EVP_PKEY (no more RSA_* calls)
    FILE* pubKeyFile = fopen(argv[2], "r");
    if (!pubKeyFile) {
        std::println(stderr, "Error: Cannot open RSA public key '{}'.", argv[2]);
        return 1;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
    fclose(pubKeyFile);
    if (!pkey) {
        std::println(stderr, "Error: PEM_read_PUBKEY failed.");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // encrypt AES key with RSA via EVP_PKEY_encrypt
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!pctx) {
        std::println(stderr, "Error: EVP_PKEY_CTX_new failed.");
        EVP_PKEY_free(pkey);
        return 1;
    }
    if (EVP_PKEY_encrypt_init(pctx) <= 0) {
        std::println(stderr, "Error: EVP_PKEY_encrypt_init failed.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        return 1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
        std::println(stderr, "Error: EVP_PKEY_CTX_set_rsa_padding failed.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // get output size
    size_t encLen = 0;
    if (EVP_PKEY_encrypt(pctx, nullptr, &encLen, reinterpret_cast<const unsigned char*>(aesKey.data()), aesKey.size()) <= 0) {
        std::println(stderr, "Error: EVP_PKEY_encrypt (size check) failed.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    std::vector<std::byte> encAesKey(encLen);
    if (EVP_PKEY_encrypt(pctx, reinterpret_cast<unsigned char*>(encAesKey.data()), &encLen, reinterpret_cast<const unsigned char*>(aesKey.data()), aesKey.size()) <= 0) {
        std::println(stderr, "Error: EVP_PKEY_encrypt failed.");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        return 1;
    }
    encAesKey.resize(encLen);

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);

    std::println("aesKey.size(): {}, encLen: {}", aesKey.size(), encLen);

    // package = [2 bytes length][RSA-encrypted key][16 bytes IV][AES ciphertext]
    std::vector<std::byte> output;
    output.reserve(2 + encAesKey.size() + aesIV.size() + ciphertext.size());

    output.push_back(std::byte((encLen >> 8) & 0xFF));
    output.push_back(std::byte(encLen & 0xFF));
    output.insert(output.end(), encAesKey.begin(), encAesKey.end());
    output.insert(output.end(), aesIV.begin(), aesIV.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());

    if (!writeFile(argv[3], output)) {
        std::println(stderr, "Error: Failed to write encrypted file '{}'.", argv[3]);
        return 1;
    }
    std::println("encryption successful. File stored in '{}'.", argv[3]);
    return 0;
}
