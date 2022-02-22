//
// Created by 何剑虹 on 2020/10/25.
//

#ifndef CPP_MPC_RAND_H
#define CPP_MPC_RAND_H

#include "bn.h"

namespace safeheron {
namespace rand {

bool RandomBytes(unsigned char * buf, size_t size);
safeheron::bignum::BN RandomBN(size_t byteSize);
safeheron::bignum::BN RandomBNStrict(size_t byteSize);
safeheron::bignum::BN RandomPrime(size_t byteSize);
safeheron::bignum::BN RandomPrimeStrict(size_t byteSize);
safeheron::bignum::BN RandomSafePrime(size_t byteSize);
safeheron::bignum::BN RandomBNLt(const safeheron::bignum::BN &max);
safeheron::bignum::BN RandomBNLtGcd(const safeheron::bignum::BN &max);

};
};


#endif //CPP_MPC_RAND_H