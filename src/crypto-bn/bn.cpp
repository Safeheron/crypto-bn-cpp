//
// Created by 何剑虹 on 2020/8/31.
//

#include "bn.h"
#include <cassert>
#include <cstring>
#include <sstream>
#include <string>
#include <openssl/bn.h>
#include "../exception/exceptions.h"

namespace safeheron {
namespace bignum {

/**
 * const variables definition
*/
const BN BN::ZERO = BN(); // same as BN(0)
const BN BN::ONE = BN(1);
const BN BN::TWO = BN(2);
const BN BN::THREE = BN(3);
const BN BN::FOUR = BN(4);
const BN BN::FIVE = BN(5);
const BN BN::MINUS_ONE = BN(-1);

/**
 * Construct a BN object and initialized it with 0
*/
BN::BN()
        : bn_(nullptr)
{
    if (!(bn_ = BN_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    // BN_zero() never fails and returns no value.
    BN_zero(bn_);
}
/**
 * Construct a BN object and initialized it with parameter i
*/
BN::BN(long i)
        : bn_(nullptr)
{
    int ret = 0;
    if (!(bn_ = BN_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
    if (i >= 0) {
        if ((ret = BN_set_word(bn_, i)) != 1) {
            BN_clear_free(bn_);
            bn_ = nullptr;
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    else {
        if ((ret = BN_set_word(bn_, -i) ) != 1) {
            BN_clear_free(bn_);
            bn_ = nullptr;
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
        BN_set_negative(bn_, 1);
    }
}
/**
 * Construct a BN objet and initialized it with str
 *
 * str: a 2/10/16 radix number string
 * base: the radix, only support 2/10/16 radix
 *
*/
BN::BN(const char *str, int base)
        : bn_(nullptr)
{
    assert(str);
    assert(base == 2 || base == 10 || base == 16);

    int ret = 0;
    if (!(bn_ = BN_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, 0);
    }

    switch (base)
    {
        case 2:
        {
            std::string hex_str;
            std::stringstream ss;
            ss << std::hex << std::stoi(str, nullptr, 2);
            ss >> hex_str;
            if ((ret = BN_hex2bn(&bn_, hex_str.c_str())) <= 0) {
                BN_clear_free(bn_);
                bn_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
            }
            break;
        }
        case 10:
            if ((ret = BN_dec2bn(&bn_, str)) <= 0) {
                BN_clear_free(bn_);
                bn_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
            }
            break;
        case 16:
            if ((ret = BN_hex2bn(&bn_, str)) <= 0) {
                BN_clear_free(bn_);
                bn_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
            }
            break;
        default:
            if ((ret = BN_set_word(bn_, 0)) != 1) {
                BN_clear_free(bn_);
                bn_ = nullptr;
                throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
            }
            break;
    }
}
/**
 * Destruction
*/
BN::~BN()
{
    if (bn_) {
        BN_clear_free(bn_);
        bn_ = nullptr;
    }
}
/**
 * A copy constructor
 * Dump the BIGNUM object from num
*/
BN::BN(const BN &num)
        : bn_(nullptr)
{
    if (!(bn_ = BN_dup(num.bn_))) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
}
/**
 * A copy assignment
 * Return a copy BIGNUM object from num
*/
BN &BN::operator=(const BN &num)
{
    assert(bn_);
    if (this == &num) {
        return *this;
    }
    if (!(BN_copy(bn_, num.bn_))) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
    return *this;
}
/**
 * A move constructor
 * move BIGNUM object pointer from num to this
*/
BN::BN(BN &&num) noexcept
        : bn_(nullptr)
{
    bn_ = num.bn_;
    num.bn_ = nullptr;
}
/**
 * A move assignment
 * move BIGNUM object pointer from num to this, and return it
*/
BN &BN::operator=(BN &&num) noexcept
{
    if (this == &num) {
        return *this;
    }
    if (bn_) {
        BN_clear_free(bn_);
        bn_ = nullptr;
    }
    bn_ = num.bn_;
    num.bn_ = nullptr;
    return *this;
}
/**
 * Add the BIGNUM num with this, and return the result
*/
BN BN::operator+(const BN &num) const
{
    BN n;
    int ret = 0;
    assert(bn_ && n.bn_ && num.bn_);
    if ((ret = BN_add(n.bn_, bn_, num.bn_)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return n;
}
/**
 * Sub the BIGNUM num from this, and return the result
*/
BN BN::operator-(const BN &num) const
{
    BN n;
    int ret = 0;
    assert(bn_ && n.bn_ && num.bn_);
    if ((ret = BN_sub(n.bn_, bn_, num.bn_)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return n;
}
/**
 * Mul the BIGNUM num with this, and return the result
*/
BN BN::operator*(const BN &num) const
{
    BN n;
    BN_CTX* ctx = nullptr;
    int ret = 0;

    assert(bn_ && n.bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = BN_mul(n.bn_, bn_, num.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return n;
}
/**
 * Div the BIGNUM num with this, and return the result
*/
BN BN::operator/(const BN &num) const
{
    BN n;
    BN_CTX* ctx = nullptr;
    int ret = 0;

    assert(bn_ && n.bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = BN_div(n.bn_, nullptr, bn_, num.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return n;
}
/**
 * Add the BIGNUM num with this
*/
BN &BN::operator+=(const BN &num)
{
    int ret = 0;
    assert(bn_ && num.bn_);
    if ((ret = BN_add(bn_, bn_, num.bn_)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return *this;
}
/**
 * Sub the BIGNUM num from this
*/
BN &BN::operator-=(const BN &num)
{
    int ret = 0;
    assert(bn_ && num.bn_);
    if ((ret = BN_sub(bn_, bn_, num.bn_)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return *this;
}
/**
 * Mul the BIGNUM num with this
*/
BN &BN::operator*=(const BN &num)
{
    int ret = 0;
    BN_CTX* ctx = nullptr;

    assert(bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = BN_mul(bn_, bn_, num.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return *this;
}
/**
 * Div the BIGNUM num by this
*/
BN &BN::operator/=(const BN &num)
{
    int ret = 0;
    BN_CTX* ctx = nullptr;

    assert(bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = BN_div(bn_, nullptr, bn_, num.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return *this;
}
/**
 * Add the long value si with this, and return the result
*/
BN BN::operator+(long si) const
{
    int ret = 0;
    BN n(*this);

    assert(n.bn_);

    if (si >= 0) {
        if ((ret = BN_add_word(n.bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    } else {
        if ((ret = BN_sub_word(n.bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    return n;
}
/**
 * Sub the long value si from this, and return the result
*/
BN BN::operator-(long si) const
{
    int ret = 0;
    BN n(*this);

    assert(n.bn_);

    if (si >= 0) {
        if ((ret = BN_sub_word(n.bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    } else {
        if ((ret = BN_add_word(n.bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    return n;
}
/**
 * Mul the long value si with this, and return the result
*/
BN BN::operator*(long si) const
{
    int ret = 0;
    BN n(*this);

    assert(n.bn_);

    if (si >= 0) {
        if ((ret = BN_mul_word(n.bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    else {
        BN_set_negative(n.bn_, 1);
        if ((ret = BN_mul_word(n.bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    return n;
}
/**
 * Div the long value si with this, and return the result
*/
BN BN::operator/(long si) const
{
    BN n(*this);
    unsigned long ret = 0;

    assert(n.bn_);
    if (si >= 0) {
        if ((ret = BN_div_word(n.bn_, si)) == (BN_ULONG)-1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    else {
        BN_set_negative(n.bn_, 1);
        if ((ret = BN_div_word(n.bn_, -si)) == (BN_ULONG)-1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    return n;
}
/**
 * Add the long value si with this
*/
BN &BN::operator+=(long si)
{
    int ret = 0;

    assert(bn_);
    if (si >= 0) {
        if ((ret = BN_add_word(bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    } else {
        if ((ret = BN_sub_word(bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    return *this;
}
/**
 * Sub the long value si from this
*/
BN &BN::operator-=(long si)
{
    int ret = 0;

    assert(bn_);
    if (si >= 0) {
        if ((ret = BN_sub_word(bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    } else {
        if ((ret = BN_add_word(bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    return *this;
}
/**
 * Mul the long value si with this
*/
BN &BN::operator*=(long si)
{
    int ret = 0;

    assert(bn_);
    if (si >= 0) {
        if ((ret = BN_mul_word(bn_, si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    else {
        BN_set_negative(bn_, 1);
        if ((ret = BN_mul_word(bn_, -si)) != 1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    return *this;
}
/**
 * Div the long value si with this
*/
BN &BN::operator/=(long si)
{
    unsigned long ret = 0;

    assert(bn_);
    if (si >= 0) {
        if ((ret = BN_div_word(bn_, si)) == (BN_ULONG)-1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    } else {
        BN_set_negative(bn_, 1);
        if ((ret = BN_div_word(bn_, -si)) == (BN_ULONG)-1) {
            throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
        }
    }
    return *this;
}
/**
 * Mod the BIGNUM num with this, and return the result
*/
BN BN::operator%(const BN &num) const
{
    int ret = 0;
    BN n(*this);
    BN_CTX* ctx = nullptr;

    assert(bn_ && n.bn_ && num.bn_);

    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = BN_nnmod(n.bn_, n.bn_, num.bn_, ctx)) != 1){
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return n;
}
/**
 * Mod the ULONG value ui with this, and return the result
*/
BN BN::operator%(unsigned long ui) const
{
    int ret = 0;
    assert(bn_);
    if ((ret = BN_mod_word(bn_, ui)) == -1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return BN(ret);
}
/**
 * Shift this to left by ui bits, and return the result
*/
BN BN::operator<<(unsigned long ui) const
{
    BN n;
    int ret = 0;
    assert(bn_ && n.bn_);
    if ((ret = BN_lshift(n.bn_, bn_, ui)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return n;
}
/**
 * Shift this to right by ui bits, and return the result
*/
BN BN::operator>>(unsigned long ui) const
{
    BN n;
    int ret = 0;
    assert(bn_ && n.bn_);
    if ((ret = BN_rshift(n.bn_, bn_, ui)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return n;
}
/**
 * Shift this to left by ui bits
*/
BN &BN::operator<<=(unsigned long ui)
{
    int ret = 0;
    assert(bn_);
    if ((ret = BN_lshift(bn_, bn_, ui)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return *this;
}
/**
 * Shift this to right by ui bits
*/
BN &BN::operator>>=(unsigned long ui)
{
    int ret = 0;
    assert(bn_);
    if ((ret = BN_rshift(bn_, bn_, ui)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return *this;
}
/**
 * Return true if this.bn_ = num.bn_
*/
bool BN::operator==(const BN &num) const
{
    return BN_cmp(bn_, num.bn_) == 0;
}
/**
 * Return true if this.bn_ != num.bn_
*/
bool BN::operator!=(const BN &num) const
{
    return BN_cmp(bn_, num.bn_) != 0;
}
/**
 * Return true if this.bn_ < num.bn_
*/
bool BN::operator<(const BN &num) const
{
    return BN_cmp(bn_, num.bn_) == -1;
}
/**
 * Return true if this.bn_ <= num.bn_
*/
bool BN::operator<=(const BN &num) const
{
    return BN_cmp(bn_, num.bn_) <= 0;
}
/**
 * Return true if this.bn_ > num.bn_
*/
bool BN::operator>(const BN &num) const
{
    return BN_cmp(bn_, num.bn_) == 1;
}
/**
 * Return true if this.bn_ >= num.bn_
*/
bool BN::operator>=(const BN &num) const
{
    return BN_cmp(bn_, num.bn_) >= 0;
}
/**
 * Return true if this.bn_ = si
*/
bool BN::operator==(long si) const
{
    BN n(si);
    return *this == n;
}
/**
 * Return true if this.bn_ != si
*/
bool BN::operator!=(long si) const
{
    BN n(si);
    return *this != n;
}
/**
 * Return true if this.bn_ > si
*/
bool BN::operator>(long si) const
{
    BN n(si);
    return *this > n;
}
/**
 * Return true if this.bn_ < si
*/
bool BN::operator<(long si) const
{
    BN n(si);
    return *this < n;
}
/**
 * Return true if this.bn_ >= si
*/
bool BN::operator>=(long si) const
{
    BN n(si);
    return *this >= n;
}
/**
 * Return true if this.bn_ <= si
*/
bool BN::operator<=(long si) const
{
    BN n(si);
    return *this <= n;
}
/**
 * Return the negative of this
*/
BN BN::Neg() const
{
    BN n(*this);
    if (n.IsNeg()) {
        BN_set_negative(n.bn_, 0);
    }
    else {
        BN_set_negative(n.bn_, 1);
    }
    return n;
}
/**
 *  Return quotient q = this / d
 *  and remainder r = this % d
*/
void BN::Div(const BN &d, BN &q, BN &r)
{
    int ret = 0;
    BN_CTX* ctx = nullptr;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = BN_div(q.bn_, r.bn_, bn_, d.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
}
/**
 *  Return the inverse of (this modulo m)
 *  Compute the inverse modulo mod. Be careful, mode must be prime!!!
*/
BN BN::InvM(const BN &m) const
{
    BN r;
    BN_CTX* ctx = nullptr;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if (!BN_mod_inverse(r.bn_, bn_, m.bn_, ctx)) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return r;
}
/**
 * Return the greatest common divisor of this and n
*/
BN BN::Gcd(const BN &n) const
{
    BN r;
    BN_CTX* ctx = nullptr;
    int ret = 0;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = BN_gcd(r.bn_, bn_, n.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return r;
}
/**
 * Return the least common multiple of this and n.
 * lcm(a, b) = ab/gcd(a,b))
*/
BN BN::Lcm(const BN &n) const
{
    BN r = (*this) * n;
    r /= Gcd(n);
    return r;
}
/**
 * Return the y-th power of this and modulo m
 * r = (this ^ y) % m
*/
BN BN::PowM(const BN &y, const BN &m) const
{
    BN r;
    BN_CTX* ctx = nullptr;
    int ret = 0;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if ((ret = BN_mod_exp(r.bn_, bn_, y.bn_, m.bn_, ctx)) != 1) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);

    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return r;
}
/**
 * Return 'r' such that
 *      r^2 == this (mod p),
*/
BN BN::SqrtM(const BN &p) const
{
    BN r;
    BN_CTX* ctx = nullptr;
    if (!(ctx = BN_CTX_new())) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, -1);
    }
    if (!(BN_mod_sqrt(r.bn_, bn_, p.bn_, ctx))) {
        BN_CTX_free(ctx);
        ctx = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
    BN_CTX_free(ctx);
    ctx = nullptr;
    return r;
}
/**
 * Return sqrt mod is exist or not
*/
bool BN::ExistSqrtM(const BN &p) const
{
    BN p_minus_1 = p - 1;
    BN lpow = p_minus_1 >> 1; // lpow = (p-1)/2
    BN n = *this % p;
    if (n.IsZero()) return true;
    if (n.PowM(lpow, p) == BN::ONE) {
        return true;
    } else{
        return false;
    }
}
/**
 * Return true is this is a prime, otherwise return false
*/
bool BN::IsProbablyPrime() const
{
    return BN_is_prime_fasttest_ex(bn_, 0, nullptr, 1, nullptr);
}
/**
 * Construct a BN object from HEX char*
*/
BN BN::FromHexStr(const char *str)
{
    assert(str);

    BN n;
    int ret = 0;
    if (n.bn_) {
        BN_clear_free(n.bn_);
        n.bn_ = nullptr;
    }
    if ((ret = BN_hex2bn(&n.bn_, str)) == 0) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return n;
}
/**
 * Construct a BN object from HEX string
*/
BN BN::FromHexStr(const std::string &str)
{
    return BN::FromHexStr(str.c_str());
}
/**
 * Construct a BN object from DEC char*
*/
BN BN::FromDecStr(const char *str)
{
    assert(str);

    BN n;
    int ret = 0;
    if (n.bn_) {
        BN_clear_free(n.bn_);
        n.bn_ = nullptr;
    }
    if ((ret = BN_dec2bn(&n.bn_, str)) == 0) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
    return n;
}
/**
 * Construct a BN object from DEC string
*/
BN BN::FromDecStr(const std::string &str)
{
    return BN::FromDecStr(str.c_str());
}
/**
 * Convert this BIGNUM bits to a HEX string
*/
void BN::ToHexStr(std::string &str) const
{
    char *ch = BN_bn2hex((const BIGNUM*)bn_);
    if (ch == nullptr) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }

    str.assign(ch, strlen(ch));
    OPENSSL_free(ch);
    ch = nullptr;
}
/**
 * Convert this BIGNUM bits to a DEC string
*/
void BN::ToDecStr(std::string &str) const
{
    char *ch = BN_bn2dec((const BIGNUM*)bn_);
    if (ch == nullptr) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }

    str.assign(ch, strlen(ch));
    OPENSSL_free(ch);
    ch = nullptr;
}
/**
 * Construct a BN object from byte buffer, in big endian
*/
BN BN::FromBytesBE(const uint8_t *buf, int len)
{
    assert(buf);

    BN n;
    if (!BN_bin2bn(buf, len, n.bn_)) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
    return n;
}
/**
 * Construct a BN object from byte string, in big endian
*/
BN BN::FromBytesBE(std::string &buf)
{
    return FromBytesBE((const uint8_t *)buf.c_str(), buf.length());
}
/**
 * Construct a BN object from byte buffer, in little endian
*/
BN BN::FromBytesLE(const uint8_t *buf, int len)
{
    assert(buf);

    BN n;
    if (!BN_lebin2bn(buf, len, n.bn_)) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, 0);
    }
    return n;
}
/**
 * Construct a BN object from byte string, in little endian
*/
BN BN::FromBytesLE(std::string &buf)
{
    return FromBytesLE((const uint8_t *)buf.c_str(), buf.length());
}
/**
 * Convert this BIGNUM to bytes string, in big endian
*/
void BN::ToBytesBE(std::string &buf) const
{
    int len = BN_num_bytes(bn_);
    if (len == 0 ) {
        buf.clear();
        return;
    }

    uint8_t* ch = (uint8_t*)OPENSSL_malloc(len);
    if (ch == nullptr) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, len);
    }

    memset(ch, 0, len);
    if ((len = BN_bn2bin(bn_, ch)) <= 0) {
        OPENSSL_free(ch);
        ch = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, len);
    }

    buf.assign((const char*)ch, len);
    OPENSSL_free(ch);
    ch = nullptr;
}
/**
 * Convert this BIGNUM to bytes string, in little endian
*/
void BN::ToBytesLE(std::string &buf) const
{
    int len = BN_num_bytes(bn_);
    if (len == 0 ) {
        buf.clear();
        return;
    }

    uint8_t* ch = (uint8_t*)OPENSSL_malloc(len);
    if (ch == nullptr) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, len);
    }

    memset(ch, 0, len);
    if ((len = BN_bn2lebinpad(bn_, ch, len)) <= 0) {
        OPENSSL_free(ch);
        ch = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, len);
    }

    buf.assign((const char*)ch, len);
    OPENSSL_free(ch);
    ch = nullptr;
}
/**
 * Convert this BIGNUM to 32 bytes buff, in big endian
*/
void BN::ToBytes32BE(uint8_t *buf32, int blen) const
{
    assert(buf32);
    assert(blen >= 32);
    memset(buf32, 0, 32);

    int len = BN_num_bytes(bn_);
    if (len == 0) {
        return;
    }

    uint8_t*ch = (uint8_t*)OPENSSL_malloc(len);
    if (ch == nullptr) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, len);
    }

    memset(ch, 0, len);
    if ((len = BN_bn2bin(bn_, ch)) <= 0) {
        OPENSSL_free(ch);
        ch = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, len);
    }

    if (len < 32) {
        uint8_t *des = buf32 + 32 - len;
        memcpy(des, ch, len);
    } else {
        uint8_t *src = ch + len - 32;
        memcpy(buf32, src, 32);
    }

    OPENSSL_free(ch);
    ch = nullptr;
}
/**
 * Convert this BIGNUM to 32 bytes buff, in little endian
*/
void BN::ToBytes32LE(uint8_t *buf32, int blen) const
{
    assert(buf32);
    assert(blen >= 32);
    memset(buf32, 0, 32);

    int len = BN_num_bytes(bn_);
    if (len == 0) {
        return;
    }

    uint8_t* ch = (uint8_t*)OPENSSL_malloc(len);
    if (ch == nullptr) {
        throw BadAllocException(__FILE__, __LINE__, __FUNCTION__, len);
    }

    memset(ch, 0, len);
    if ((len = BN_bn2lebinpad(bn_, ch, len)) <= 0) {
        OPENSSL_free(ch);
        ch = nullptr;
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, len);
    }

    if (len < 32) {
        memcpy(buf32, ch, len);
    }
    else {
        memcpy(buf32, ch, 32);
    }

    OPENSSL_free(ch);
    ch = nullptr;
}
/**
 * Convert this BIGNUM to 32 bytes string, in big endian
*/
void BN::ToBytes32BE(std::string &buf) const
{
    uint8_t t_buf32[32] = {0};
    ToBytes32BE(t_buf32);
    buf.assign((const char *)t_buf32, 32);
}
/**
 * Convert this BIGNUM to 32 bytes string, in little endian
*/
void BN::ToBytes32LE(std::string &buf) const
{
    uint8_t t_buf32[32];
    ToBytes32LE(t_buf32);
    buf.assign((const char *)t_buf32, 32);
}
/**
 * Hold no a new BIGNUM object specified by bn
 * bn should be new and initialized before calling this API，
 * and don't free it by hand, it will be freed auto in distruction
*/
void BN::Hold(bignum_st* bn)
{
    assert(bn);
    if (bn_) {
        BN_clear_free(bn_);
        bn_ = nullptr;
    }
    bn_ = bn;
}
/**
 * Return bits size of this BIGNUM
*/
int BN::BitLength() const
{
    return BN_num_bits(bn_);
}
/**
 * Return bytes size of this BIGNUM
*/
int BN::ByteLength() const
{
    int bitLen = BitLength();
    return (bitLen % 8 == 0) ? (bitLen / 8) : (1 + bitLen / 8);
}
/**
 * Return true if this BIGUN is a negative number
*/
int BN::IsNeg() const
{
    return BN_is_negative(bn_) == 1;
}
/**
 * Return true if this BIGUN is a even number
*/
int BN::IsEven() const
{
    return !IsOdd();
}
/**
 * Return true if this BIGUN is an odd number
*/
int BN::IsOdd() const
{
    return BN_is_odd(bn_) == 1;
}
/**
 * Return true if this BIGUN is 0
*/
int BN::IsZero() const
{
    return BN_is_zero(bn_) == 1;
}
/**
 * Return the max one between a and b
*/
BN BN::Max(const BN &a, const BN &b)
{
    return (a > b) ? a : b;
}
/**
 * Return the min one between a and b
*/
BN BN::Min(const BN &a, const BN &b)
{
    return (a < b) ? a : b;
}
/**
 * Swap the values between a and b
*/
void BN::Swap(BN &a, BN &b)
{
    assert(a.bn_ && b.bn_);
    BN_swap(a.bn_, b.bn_);
}
/**
 * Set bits for this BIGNUM
*/
void BN::SetBit(unsigned long bit_index)
{
    assert(bn_);

    int ret = 0;
    if ((ret = BN_set_bit(bn_, bit_index)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
}
/**
 * Clean bits for this BIGNUM
*/
void BN::ClearBit(unsigned long bit_index)
{
    assert(bn_);

    int ret = 0;
    if ((ret = BN_clear_bit(bn_, bit_index)) != 1) {
        throw OpensslException(__FILE__, __LINE__, __FUNCTION__, ret);
    }
}
/**
 * Return true if this BIGNUM bit is set
*/
bool BN::IsBitSet(unsigned long bit_index) const
{
    assert(bn_);
    return BN_is_bit_set(bn_, bit_index) == 1;
}
/**
 * Return the string of this BIGNUM
*/
std::string BN::Inspect(int base) const
{
    assert(base == 10 || base == 16);

    std::string str;
    if (base == 10) {
        ToDecStr(str);
    }
    else {
        ToHexStr(str);
    }
    return str;
}

}
}
