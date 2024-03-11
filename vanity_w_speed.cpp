#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <secp256k1.h>
#include <openssl/evp.h>
#include <thread>
#include <atomic>
#include <vector>

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


std::atomic<bool> found(false);
std::atomic<unsigned long long> count(0);
std::string foundPrivateKey;
std::string foundAddress;
std::string prefix = "0x00000000";

void searchVanityAddress() {
    while (!found) {
        std::string privateKey = generatePrivateKey();
        std::string publicKey = derivePublicKey(privateKey);
        std::string address = deriveEthereumAddress(publicKey);
        ++count;

        if (address.substr(0, prefix.length()) == prefix) {
            found = true;
            foundPrivateKey = privateKey;
            foundAddress = address;
            break;
        }
    }
}

int main() {
    auto start = std::chrono::steady_clock::now();
    auto lastUpdate = start;

    std::vector<std::thread> threads;
    for (int i = 0; i < 32; ++i) {
        threads.emplace_back(searchVanityAddress);
    }

    while (!found) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastUpdate).count();

        if (elapsed >= 1) {
            auto totalElapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
            if (totalElapsed > 0) {
                std::cout << "Addresses checked per second: " << count / totalElapsed << std::endl;
            }
            lastUpdate = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    for (auto& thread : threads) {
        thread.join();
    }

    if (found) {
        std::cout << "Private Key: " << foundPrivateKey << std::endl;
        std::cout << "Vanity Address: " << foundAddress << std::endl;
    }

    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
    if (elapsed > 0) {
        std::cout << "Final rate: Addresses checked per second: " << count / elapsed << std::endl;
    }

    return 0;
}