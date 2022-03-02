//
// Created by 何剑虹 on 2020/8/31.
//

#ifndef SAFEHERON_BIG_NUMBER_H
#define SAFEHERON_BIG_NUMBER_H

#include <iostream>

struct bignum_st;

namespace safeheron {
namespace bignum {

class BN {
public:
    /**
     * Construct a BN object and initialized it with 0
    */
    explicit BN();
    /**
     * Construct a BN object and initialized it with word i
    */
    explicit BN(long i);
    /**
     * Construct a BN objet and initialized it with str
     *
     * str: a 2/10/16 radix number string
     * base: the radix, only support 2/10/16 radix
     *
    */
    explicit BN(const char *str, int base);
    /**
     * A copy constructor
     * Dump the BIGNUM object from num
    */
    BN(const BN &num);
    /**
     * A copy assignment constructor
     * Return a copy BIGNUM object from num
    */
    BN &operator=(const BN &num);
    /**
     * A move constructor
     * move BIGNUM object pointer from num to this
    */
    BN(BN &&num) noexcept;
    /**
     * A move assignment
     * move BIGNUM object pointer from num to this, and return it
    */
    BN &operator=(BN &&num) noexcept;
    /**
     * Destruction
    */
    virtual ~BN();
    /**
     * Add the BIGNUM num with this, and return the result
    */
    BN operator+(const BN &num) const;
    /**
     * Sub the BIGNUM num from this, and return the result
    */
    BN operator-(const BN &num) const;
    /**
     * Mul the BIGNUM num with this, and return the result
    */
    BN operator*(const BN &num) const;
    /**
     * Div the BIGNUM num with this, and return the result
    */
    BN operator/(const BN &num) const;
    /**
     * Add the BIGNUM num with this
    */
    BN &operator+=(const BN &num);
    /**
     * Sub the BIGNUM num from this
    */
    BN &operator-=(const BN &num);
    /**
     * Mul the BIGNUM num with this
    */
    BN &operator*=(const BN &num);
    /**
     * Div the BIGNUM num by this
    */
    BN &operator/=(const BN &num);
    /**
     * Add the long value si with this, and return the result
    */
    BN operator+(long n) const;
    /**
     * Sub the long value si from this, and return the result
    */
    BN operator-(long n) const;
    /**
     * Mul the long value si with this, and return the result
    */
    BN operator*(long n) const;
    /**
     * Div the long value si with this, and return the result
    */
    BN operator/(long n) const;
    /**
     * Add the long value si with this
    */
    BN &operator+=(long n);
    /**
     * Sub the long value si from this
    */
    BN &operator-=(long n);
    /**
     * Mul the long value si with this
    */
    BN &operator*=(long n);
    /**
     * Div the long value si with this
    */
    BN &operator/=(long n);
    /**
     * Mod the BIGNUM num with this, and return the result
    */
    BN operator%(const BN &num) const;
    /**
     * Mod the ULONG value ui with this, and return the result
    */
    BN operator%(unsigned long n) const;
    /**
     * Shift this to left by ui bits, and return the result
    */
    BN operator<<(unsigned long n) const;
    /**
     * Shift this to right by ui bits, and return the result
    */
    BN operator>>(unsigned long n) const;
    /**
     * Shift this to left by ui bits
    */
    BN &operator<<=(unsigned long n);
    /**
     * Shift this to right by ui bits
    */
    BN &operator>>=(unsigned long n);
    /**
     * Return true if this._bn = num._bn
    */
    bool operator==(const BN &num) const;
    /**
     * Return true if this._bn != num._bn
    */
    bool operator!=(const BN &num) const;
    /**
     * Return true if this._bn > num._bn
    */
    bool operator>(const BN &num) const;
    /**
     * Return true if this._bn < num._bn
    */
    bool operator<(const BN &num) const;
    /**
     * Return true if this._bn >= num._bn
    */
    bool operator>=(const BN &num) const;
    /**
     * Return true if this._bn <= num._bn
    */
    bool operator<=(const BN &num) const;
    /**
     * Return true if this._bn = si
    */
    bool operator==(long si) const;
    /**
     * Return true if this._bn != si
    */
    bool operator!=(long si) const;
    /**
     * Return true if this._bn > si
    */
    bool operator>(long si) const;
    /**
     * Return true if this._bn < si
    */
    bool operator<(long si) const;
    /**
     * Return true if this._bn >= si
    */
    bool operator>=(long si) const;
    /**
     * Return true if this._bn <= si
    */
    bool operator<=(long si) const;
    /**
     * Return the negative of this
    */
    BN Neg()const;
    /**
     *  Return quotient q = this / d
     *  and remainder r = this % d
    */
    void Div(const BN &d, BN &q, BN &r);
    /**
     *  Return the inverse of (this modulo m)
     *  Compute the inverse modulo mod. Be careful, mode must be prime!!!
    */
    BN InvM(const BN &m) const;
    /**
     * Return the greatest common divisor of this and n
    */
    BN Gcd(const BN &n) const;
    /**
     * Return the least common multiple of this and n.
     * lcm(a, b) = ab/gcd(a,b))
    */
    BN Lcm(const BN &n) const;
    /**
     * Return the y-th power of this and modulo m
     * r = (this ^ y) % m
    */
    BN PowM(const BN &y, const BN &m) const;
    /**
     * Get square root on modulo m
     * Return 'r' such that
     *      r^2 == this (mod p),
    */
    BN SqrtM(const BN &m) const;
    /**
     * Return sqrt mod is exist or not
    */
    bool ExistSqrtM(const BN &m) const;
    /**
     * Return true is this is a prime, otherwise return false
    */
    bool IsProbablyPrime() const;
    /**
     * Construct a BN object from HEX char*
    */
    static BN FromHexStr(const char *str);
    /**
     * Construct a BN object from HEX string
    */
    static BN FromHexStr(const std::string &str);
    /**
     * Construct a BN object from DEC char*
    */
    static BN FromDecStr(const char *str);
    /**
     * Construct a BN object from DEC string
    */
    static BN FromDecStr(const std::string &str);
    /**
     * Convert this BIGNUM bits to a HEX string
    */
    void ToHexStr(std::string &str) const;
    /**
     * Convert this BIGNUM bits to a DEC string
    */
    void ToDecStr(std::string &str) const;
    /**
     * Construct a BN object from byte buffer, in big endian
    */
    static BN FromBytesBE(const uint8_t *buf, int len);
    /**
     * Construct a BN object from byte string, in big endian
    */
    static BN FromBytesBE(std::string &buf);
    /**
     * Construct a BN object from byte buffer, in little endian
    */
    static BN FromBytesLE(const uint8_t *buf, int len);
    /**
     * Construct a BN object from byte string, in little endian
    */
    static BN FromBytesLE(std::string &buf);
    /**
     * Convert this BIGNUM to bytes string, in big endian
    */
    void ToBytesBE(std::string &buf) const;
    /**
     * Convert this BIGNUM to bytes string, in little endian
    */
    void ToBytesLE(std::string &buf) const;
    /**
     * Convert this BIGNUM to 32 bytes buff, in big endian
    */
    void ToBytes32BE(std::string &buf) const;
    /**
     * Convert this BIGNUM to 32 bytes buff, in little endian
    */
    void ToBytes32LE(std::string &buf) const;
    /**
     * Convert this BIGNUM to 32 bytes string, in big endian
    */
    void ToBytes32BE(uint8_t *buf32, int blen=32) const;
    /**
     * Convert this BIGNUM to 32 bytes string, in little endian
    */
    void ToBytes32LE(uint8_t *buf32, int blen=32) const;
    /**
     * Hold no a new BIGNUM object specified by bn
     * bn should be new and initialized before calling this API，
     * and don't free it by hand, it will be freed auto in distruction
    */
    void Hold(bignum_st* bn);
    /**
     * Return bits size of this BIGNUM
    */
    int BitLength() const;
    /**
     * Return bytes size of this BIGNUM
    */
    int ByteLength() const;
    /**
     * Return true if this BIGUN is a negative number
    */
    int IsNeg() const;
    /**
     * Return true if this BIGUN is a even number
    */
    int IsEven() const;
    /**
     * Return true if this BIGUN is an odd number
    */
    int IsOdd() const;
    /**
     * Return true if this BIGUN is 0
    */
    int IsZero() const;
    /**
     * Return the max one between a and b
    */
    static BN Max(const BN &a, const BN &b);
    /**
     * Return the min one between a and b
    */
    static BN Min(const BN &a, const BN &b);
    /**
     * Swap the values between a and b
    */
    static void Swap(BN &a, BN &b);
    /**
     * Set bits for this BIGNUM
    */
    void SetBit(unsigned long bit_index);
    /**
     * Clean bits for this BIGNUM
    */
    void ClearBit(unsigned long bit_index);
    /**
     * Return true if this BIGNUM bit is set
    */
    bool IsBitSet(unsigned long bit_index) const;
    /**
     * Return the string of this BIGNUM
    */
    std::string Inspect(int base = 16) const;
    /**
     * Return BIGNUM pointer of bn_
     */
    const bignum_st* GetBIGNUM() const;

public:
    /**
     * const variables definition
    */
    static const BN ZERO;
    static const BN ONE;
    static const BN TWO;
    static const BN THREE;
    static const BN FOUR;
    static const BN FIVE;

    static const BN MINUS_ONE;
private:
    // BIGNUM object
    struct bignum_st* bn_;
};

};
};

#endif //SAFEHERON_BIG_NUMBER_H