#include <cstddef>
#include <cstdio>
#include <format>
#include <fstream>
#include <memory>
#include <openssl/bn.h>
#include <openssl/core_names.h> // OSSL_PKEY_PARAM_RSA_N, OSSL_PKEY_PARAM_RSA_E, ...
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <print>
#include <string_view>

// Reads an entire file into memory (if you need it, but not strictly used in this snippet).
// If reading large files, prefer a stream approach.
// Omitted here for brevity or if you want to keep as is.

static void inspectRSAPublicKey(const EVP_PKEY* pkey) {
    // We'll retrieve the modulus ("n") and exponent ("e") via the new OSSL param API.
    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) <= 0) {
        std::println(stderr, "Error: Could not retrieve RSA modulus (n).");
    }
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) <= 0) {
        std::println(stderr, "Error: Could not retrieve RSA exponent (e).");
    }

    if (n) {
        char* nHex = BN_bn2hex(n);
        if (nHex) {
            std::println("Modulus (n): {}", nHex);
            OPENSSL_free(nHex);
        }
    }
    if (e) {
        char* eHex = BN_bn2hex(e);
        if (eHex) {
            std::println("Exponent (e): {}", eHex);
            OPENSSL_free(eHex);
        }
    }

    BN_free(n);
    BN_free(e);

    // RSA key size: get the bit length, then we can show bytes (bitLength / 8)
    int bitLen = 0;
    if (EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_BITS, &bitLen) <= 0) {
        std::println(stderr, "Warning: Could not retrieve RSA key bit length.");
    } else {
        std::println("RSA key size: {} bits ({} bytes)", bitLen, bitLen / 8);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::println("usage: {} <public_key.pem>", argv[0]);
        return 1;
    }
    FILE* fp = fopen(argv[1], "r");
    if (!fp) {
        std::println(stderr, "Unable to open public key file '{}'", argv[1]);
        return 1;
    }

    // Modern approach: read into EVP_PKEY rather than RSA*
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey) {
        std::println(stderr, "Unable to read a public key from '{}'", argv[1]);
        ERR_print_errors_fp(stderr); // Print details from OpenSSL
        return 1;
    }

    inspectRSAPublicKey(pkey);

    EVP_PKEY_free(pkey);
    return 0;
}
