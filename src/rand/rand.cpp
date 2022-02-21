//
// Created by 何剑虹 on 2020/10/25.
//
#include "rand.h"
#include "../exception/exceptions.h"
#include <fcntl.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <memory>


namespace ntl{

bool Rand::RandomBytes(unsigned char *buf, size_t size) {
    int ret = 0;
    if (!buf) {
        throw RandomSourceException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = RAND_bytes(buf, size)) <= 0) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return true;
}

BN Rand::RandomBN(size_t byteSize) {
    BN n;
    std::unique_ptr<unsigned char[]> buf(new(std::nothrow) unsigned char[byteSize]);
    if (buf == nullptr) throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, byteSize);
    do{
        RandomBytes(buf.get(), byteSize);
        n = BN::FromBytesBE(buf.get(), byteSize);
    }while(n == 0);
    return n;
}

BN Rand::RandomBNStrict(size_t byteSize) {
    std::unique_ptr<unsigned char[]> buf(new(std::nothrow) unsigned char[byteSize]);
    if (buf == nullptr) throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, byteSize);
    do {
        RandomBytes(buf.get(), byteSize);
    }while((buf[0] & 0x80) == 0);
    BN n = BN::FromBytesBE(buf.get(), byteSize);
    return n;
}

BN Rand::RandomPrime(size_t byteSize) {
    BN n;
    BIGNUM* p = nullptr;
    int ret = 0;
    if (!(p = BN_new())) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
    if ((ret = BN_generate_prime_ex(p, byteSize * 8, 0, nullptr, nullptr, nullptr)) != 1) {
        BN_clear_free(p);
        p = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    n.Hold(p);
    return n;
}

BN Rand::RandomPrimeStrict(size_t byteSize) {
    BN n;
    do {
        n = RandomPrime(byteSize);
    }while (!n.IsBitSet(8*byteSize-1));
    return n;
}

BN Rand::RandomSafePrime(size_t byteSize) {
    BN n;
    BIGNUM* p = nullptr;
    int ret = 0;
    if (!(p = BN_new())) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
    if ((ret = BN_generate_prime_ex(p, byteSize * 8, 1, nullptr, nullptr, nullptr)) != 1) {
        BN_clear_free(p);
        p = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    n.Hold(p);
    return n;
}

BN Rand::RandomBNLt(const BN &max) {
    BN n;
    int byteLen = max.ByteLength();
    do{
        n = RandomBN(byteLen);
    }while (n >= max);
    return n;
}

BN Rand::RandomBNLtGcd(const BN &max) {
    BN n;
    do{
        n = RandomBNLt(max);
    }while (n.Gcd(max) != 1);
    return n;
}
}
