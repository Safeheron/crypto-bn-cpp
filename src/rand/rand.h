//
// Created by 何剑虹 on 2020/10/25.
//

#ifndef CPP_MPC_RAND_H
#define CPP_MPC_RAND_H

#include "../ntl/bn.h"
namespace ntl{
class Rand {
public:
    static bool RandomBytes(unsigned char * buf, size_t size);
    static BN RandomBN(size_t byteSize);
    static BN RandomBNStrict(size_t byteSize);
    static BN RandomPrime(size_t byteSize);
    static BN RandomPrimeStrict(size_t byteSize);
    static BN RandomSafePrime(size_t byteSize);
    static BN RandomBNLt(const BN &max);
    static BN RandomBNLtGcd(const BN &max);
};
}


#endif //CPP_MPC_RAND_H