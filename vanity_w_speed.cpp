#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <secp256k1.h>
#include <openssl/evp.h>

std::string toHex(const unsigned char* data, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string generatePrivateKey() {
    unsigned char privateKey[32];
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    do {
        for (int i = 0; i < 32; ++i) {
            privateKey[i] = static_cast<unsigned char>(rand() % 256);
        }
    } while (!secp256k1_ec_seckey_verify(ctx, privateKey));
    secp256k1_context_destroy(ctx);
    return toHex(privateKey, 32);
}

std::string derivePublicKey(const std::string& privateKey) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;
    unsigned char privateKeyBytes[32];
    for (int i = 0; i < 32; ++i) {
        privateKeyBytes[i] = static_cast<unsigned char>(std::stoi(privateKey.substr(i * 2, 2), nullptr, 16));
    }
    secp256k1_ec_pubkey_create(ctx, &pubkey, privateKeyBytes);
    unsigned char publicKey[65];
    size_t pubkeyLen = 65;
    secp256k1_ec_pubkey_serialize(ctx, publicKey, &pubkeyLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_context_destroy(ctx);
    return toHex(publicKey, 65);
}


std::string deriveEthereumAddress(const std::string& publicKey) {
    unsigned char publicKeyBytes[65];
    for (int i = 0; i < 65; ++i) {
        publicKeyBytes[i] = static_cast<unsigned char>(std::stoi(publicKey.substr(i * 2, 2), nullptr, 16));
    }
    unsigned char hash[32];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if(mdctx == NULL) {
        // Handle errors here
        return "";
    }
    if(EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1) {
        // Handle errors here
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    if(EVP_DigestUpdate(mdctx, publicKeyBytes + 1, 64) != 1) {
        // Handle errors here
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    unsigned int md_len = 32;
    if(EVP_DigestFinal_ex(mdctx, hash, &md_len) != 1) {
        // Handle errors here
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    EVP_MD_CTX_free(mdctx);
    // Note: Ethereum uses the last 20 bytes of the hash.
    return "0x" + toHex(hash + 12, 20);
}


int main() {
    std::string prefix = "0x00000000";
    unsigned long long count = 0; // Count of iterations
    auto start = std::chrono::steady_clock::now(); // Start time

    while (true) {
        std::string privateKey = generatePrivateKey();
        std::string publicKey = derivePublicKey(privateKey);
        std::string address = deriveEthereumAddress(publicKey);
        ++count; // Increment count
        if (address.substr(0, prefix.length()) == prefix) {
            std::cout << "Private Key: " << privateKey << std::endl;
            std::cout << "Vanity Address: " << address << std::endl;
            break;
        }
        
        // Optionally, you can display the rate periodically (e.g., every 10,000 iterations)
        if (count % 10000 == 0) {
            auto end = std::chrono::steady_clock::now(); // Current time
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
            if (elapsed > 0) { // Prevent division by zero
                std::cout << "Addresses checked per second: " << count / elapsed << std::endl;
            }
        }
    }

    // Final rate display
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
    if (elapsed > 0) {
        std::cout << "Final rate: Addresses checked per second: " << count / elapsed << std::endl;
    }

    return 0;
}
