#include <array>
#include <cstdio>
#include <format>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <optional>
#include <print>
#include <span>
#include <string_view>
#include <vector>
#include <ykpiv/ykpiv.h>

#include "yk_common.hpp"


std::optional<std::vector<std::byte>> decryptAES(std::span<const std::byte> ciphertext, std::span<const std::byte> key, std::span<const std::byte> iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return std::nullopt;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }

    std::vector<std::byte> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int                    outLen1 = 0;
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &outLen1, reinterpret_cast<const unsigned char*>(ciphertext.data()), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }

    int outLen2 = 0;
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    plaintext.resize(outLen1 + outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::println("usage: {} <encrypted_input> <decrypted_output>", argv[0]);
        return 1;
    }

    auto fileDataOpt = readFile(argv[1]);
    if (!fileDataOpt) {
        std::println(stderr, "error: Could not open '{}' for reading.", argv[1]);
        return 1;
    }
    const auto& fileData = *fileDataOpt;
    if (fileData.size() < 18) {
        std::println(stderr, "error: Encrypted file is too short.");
        return 1;
    }

    std::uint16_t encKeyLen = (std::uint16_t(std::to_integer<unsigned>(fileData[0])) << 8) | std::to_integer<unsigned>(fileData[1]);
    if (fileData.size() < 2 + encKeyLen + 16) {
        std::println(stderr, "error: Encrypted file does not contain expected data.");
        return 1;
    }
    std::println("rsaKeyEncLen: {}", encKeyLen);

    ykpiv_state* state = nullptr;
    if (auto ret = ykpiv_init(&state, 0); ret != YKPIV_OK) {
        std::println(stderr, "error: ykpiv_init failed: {} - {}", ykpiv_strerror_name(ret), ykpiv_strerror(ret));
        return 1;
    }
    if (auto ret = ykpiv_connect(state, nullptr); ret != YKPIV_OK) {
        std::println(stderr, "error: ykpiv_connect failed: {} - {}", ykpiv_strerror_name(ret), ykpiv_strerror(ret));
        ykpiv_done(state);
        return 1;
    }

    auto rsaEncAES = std::span{fileData}.subspan(2, encKeyLen);
    auto aesIV     = std::span{fileData}.subspan(2 + encKeyLen, 16);
    auto aesCipher = std::span{fileData}.subspan(2 + encKeyLen + 16);

    std::vector<std::byte> aesData(1024);
    size_t                 aesKeyLen = aesData.size();
    if (auto ret = ykpiv_decipher_data(state, reinterpret_cast<const unsigned char*>(rsaEncAES.data()), rsaEncAES.size(), reinterpret_cast<unsigned char*>(aesData.data()), &aesKeyLen, YKPIV_ALGO_RSA2048, YKPIV_KEY_AUTHENTICATION); ret != YKPIV_OK) {
        std::println(stderr, "error: ykpiv_decipher_data failed: {} - {} - aesKeyLen: {}", ykpiv_strerror_name(ret), ykpiv_strerror(ret), aesKeyLen);
        ykpiv_done(state);
        return 1;
    }
    ykpiv_done(state);

    std::println("aesData size: {} -> {}", aesData.size(), aesKeyLen);
    aesData.resize(aesKeyLen);

    if (aesData.size() < 2 || aesData[0] != std::byte{0} || aesData[1] != std::byte{2}) {
        std::println(stderr, "Invalid PKCS#1 padding header.");
        return 1;
    }
    std::size_t sepIndex = 2;
    while (sepIndex < aesData.size() && aesData[sepIndex] != std::byte{0}) {
        ++sepIndex;
    }
    if (sepIndex >= aesData.size()) {
        std::println(stderr, "Padding separator not found.");
        return 1;
    }
    auto actualKeyLen = aesData.size() - (sepIndex + 1);
    if (actualKeyLen != 32) {
        std::println(stderr, "Unexpected AES key length after padding removal: {}", actualKeyLen);
        return 1;
    }
    std::println("actualKeySize: {}", actualKeyLen);

    auto aesKey   = std::span{aesData}.subspan(sepIndex + 1, actualKeyLen);
    auto plainOpt = decryptAES(aesCipher, aesKey, aesIV);
    if (!plainOpt) {
        std::println(stderr, "error: AES decryption failed.");
        return 1;
    }

    std::ofstream outFile(argv[2], std::ios::binary);
    if (!outFile.is_open()) {
        std::println(stderr, "error: Unable to open '{}' for writing.", argv[2]);
        return 1;
    }
    outFile.write(reinterpret_cast<const char*>(plainOpt->data()), static_cast<std::streamsize>(plainOpt->size()));

    std::println("Decryption successful. Decrypted file stored in '{}'", argv[2]);
    return 0;
}
