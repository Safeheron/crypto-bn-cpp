//
// Created by 何剑虹 on 2020/10/22.
//
#include "gtest/gtest.h"
#include <google/protobuf/stubs/common.h>
#include "../src/rand/rand.h"
#include "../src/exception/exceptions.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

using namespace ntl;

TEST(Rand, random)
{
    BN max;
    BN p("983d0dc7e7f4d64dd03dc52ce8f85e096b37cd487223301619ae143b780b90cb", 16);
    std::cout << p.IsProbablyPrime() << std::endl;


    std::string s;
    BN n = Rand::RandomBN(32);
    n.ToHexStr(s);
    std::cout << s << std::endl;

    n = Rand::RandomBNStrict(32);
    max = n;
    n.ToHexStr(s);
    std::cout << s << std::endl;

    n = Rand::RandomPrime(32);
    n.ToHexStr(s);
    std::cout << "prime(256):"  << s << std::endl;

    n = Rand::RandomPrimeStrict(32);
    n.ToHexStr(s);
    std::cout << "prime(strict 256):"  << s << std::endl;

    for( int i = 0 ; i < 10 ; i++ ){
        n = Rand::RandomPrimeStrict(1024/8);
        n.ToHexStr(s);
        std::cout << "prime(strict 1024): " << s << std::endl;
    }

    n = Rand::RandomBNLt(max);
    n.ToHexStr(s);
    std::cout << s << std::endl;

    n = Rand::RandomBNLtGcd(max);
    n.ToHexStr(s);
    std::cout << s << std::endl;
    EXPECT_TRUE(n.Gcd(max) == 1);
}

TEST(Rand, randomByte32Generator)
{
    clock_t start, finish;
    double  duration;
    start = clock();

    uint8_t b32[32];
    for(int i = 0; i < 100000; i++){
        Rand::RandomBytes(b32, 32);
        if(i % 10000 == 0) {
            std::cout << i << std::endl;
        }
    }

    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "randomByte32Generator: %f seconds\n", duration );
}

TEST(Rand, randomBNGenerator)
{
    clock_t start, finish;
    double  duration;
    start = clock();

    std::string str;
    for(int i = 0; i < 100000; i++){
        BN n = Rand::RandomBN(32);
        if(i % 10000 == 0) {
            std::cout << i << std::endl;
        }
    }

    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "randomBNGenerator: %f seconds\n", duration );
}

TEST(Rand, TestExecption)
{
    BN n;
    try{
        n = Rand::RandomBN(32000000000);
    }catch(const BadAllocException &e) {
        std::cout << "Catch BadAllocException: " << e.detail() << std::endl;
    }catch(const RandomSourceException &e) {
        std::cout << "Catch RandomSourceException: " << e.detail() << std::endl;
    }
    std::cout << n.Inspect() << std::endl;
}

TEST(Rand, PrimeGenerate)
{
    clock_t start, end;
    start = clock();
    for(int i = 0; i < 5; i++){
        int count = 0;
        while(true){
            count ++;
            BN n = Rand::RandomBN(1024/8);
            std::string str;
            if(n.IsProbablyPrime()){
                n.ToHexStr(str);
                std::cout << "prime1024(count :" << count << "): " << str << std::endl;
                break;
            }
        }
    }
    end = clock();
    std::cout << ">>>>>>>>>>>>>> time: " << double(end - start) / CLOCKS_PER_SEC << std::endl;
}

TEST(Rand, SafePrimes)
{
    BN p;
    int key_bit = 2048;
    p = Rand::RandomSafePrime(key_bit/(2 * 8));
    std::string str;
    p.ToHexStr(str);
    std::cout << "safe primes.p: " << str << std::endl;
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
