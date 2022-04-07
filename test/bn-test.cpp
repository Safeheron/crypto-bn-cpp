#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "exception/safeheron_exceptions.h"

using safeheron::bignum::BN;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;

//constructor tests for zero
TEST(BN, ZeroConstructor) {
    //test for 0
    BN bn0;
    BN bn1(0);
    BN bn2("0", 2);
    BN bn3("0", 10);
    BN bn4("0", 16);
    BN bn5 = bn0;
    BN bn6((BN()));// Move Constructor
    EXPECT_TRUE(bn0 == BN::ZERO);
    EXPECT_TRUE(bn0 == bn1);
    EXPECT_TRUE(bn0 == bn2);
    EXPECT_TRUE(bn0 == bn3);
    EXPECT_TRUE(bn0 == bn4);
    EXPECT_TRUE(bn0 == bn5);
    EXPECT_TRUE(bn0 == bn6);

    //test for +0 and -0
    BN bn10(+0);
    BN bn11(-0);
    EXPECT_TRUE(bn0 == bn10);
    EXPECT_TRUE(bn0 == bn11);
}

//constructor tests for non-zero value
TEST(BN, NonZeroConstructor) {
    //test for positive number
    BN bn0(255);
    BN bn1("11111111",2);
    BN bn2("255", 10);
    BN bn3("ff",16);
    BN bn4 = bn1;
    BN bn5(BN(255)); // Move Constructor
    EXPECT_TRUE(bn0 == bn1);
    EXPECT_TRUE(bn0 == bn2);
    EXPECT_TRUE(bn0 == bn3);
    EXPECT_TRUE(bn0 == bn4);
    EXPECT_TRUE(bn0 == bn5);
    //test for negative number
    BN bn6(-255);
    BN bn7("-11111111",2);
    BN bn8("-255",10);
    BN bn9("-ff",16);
    BN bn10 = bn6;
    BN bn11(BN(-255)); // Move constructor
    BN bn12(-256);
    EXPECT_TRUE(bn6 == bn7);
    /**********debug*************/
    std::cout << "bn9: " << bn9.Inspect(10) << std::endl;
    std::string str1, str2;
    bn6.ToDecStr(str1);
    bn7.ToDecStr(str2);
    std::cout << "str1:"<< str1 <<std::endl;
    std::cout << "str2:" << str2 <<std::endl;
    /**********debug*************/
    EXPECT_TRUE(bn6 == bn8);
    EXPECT_TRUE(bn6 == bn9);
    EXPECT_TRUE(bn6 == bn10);
    EXPECT_TRUE(bn6 == bn11);
    //test for different numbers
    EXPECT_TRUE(bn6 != bn12);
    EXPECT_TRUE(bn0 != bn6);
    EXPECT_TRUE(bn0.Neg() == bn6);
}

TEST(BN, WeirdInput) {
    //weird input for zero
    BN bn0(00000000);
    BN bn1("00000000",2);
    BN bn2("00000000",10);
    BN bn3("00000000",16);
    EXPECT_TRUE(bn0 == bn1);
    EXPECT_TRUE(bn0 == bn2);
    EXPECT_TRUE(bn0 == bn3);
    //weird input for non-zero
    BN bn4(2748);
    BN bn5(0xabc);
    BN bn6(0x0000abc);
    BN bn7("00101010111100",2);
    BN bn8("002748",10);
    BN bn9("00abc",16);
    EXPECT_TRUE(bn4 == bn5);
    EXPECT_TRUE(bn4 == bn6);
    EXPECT_TRUE(bn4 == bn7);
    EXPECT_TRUE(bn4 == bn8);
    EXPECT_TRUE(bn4 == bn9);
    //illegal input
    BN bn10("0567",2);
    BN bn11("0abc", 10);
    BN bn12("0xyz", 16);
    EXPECT_TRUE(bn0 == bn10);
    EXPECT_TRUE(bn0 == bn11);
    EXPECT_TRUE(bn0 == bn12);

    // test for decimal, .非法字符
    BN bn14("1010.1", 2);
    BN bn15("10.5", 10);
    BN bn16("a.5", 16);
    std::string  bn14_str, bn15_str, bn16_str;
    bn14.ToDecStr(bn14_str);
    bn15.ToDecStr(bn15_str);
    bn16.ToDecStr(bn16_str);
    std::cout  << "bn14_str:" << bn14_str << ", " << "bn15_str:"
               << bn15_str << ", " << "bn16_str:" << bn16_str << std::endl;
    EXPECT_TRUE((bn14 == bn15) && (bn15 == bn16));
}

TEST(BN, BigNumConstructor) {
    //64 bits
    BN bn0("1111111111111111111111111111111111111111111111111111111111111111", 2);
    BN bn1("ffffffffffffffff",16);
    EXPECT_TRUE(bn0 == bn1);
    //128 bits
    BN bn2("ffffffffffffffffffffffffffffffff",16);
    EXPECT_TRUE(bn2.BitLength() == 128);
    EXPECT_TRUE((bn2 >> 64) == bn0);
}

TEST(BN, Const) {
    BN n0(0);
    BN n1("1", 10);
    BN n2("2", 10);
    BN n3("3", 10);
    BN n4("4", 10);
    BN n5("5", 10);
    EXPECT_TRUE( BN::ZERO == n0);
    EXPECT_TRUE( BN::ONE == n1);
    EXPECT_TRUE( BN::TWO == n2);
    EXPECT_TRUE( BN::THREE == n3);
    EXPECT_TRUE( BN::FOUR == n4);
    EXPECT_TRUE( BN::FIVE == n5);
}

TEST(BN, Assigment) {
    //test for copy assignment.
    BN bn0;
    BN bn1(1);
    EXPECT_TRUE(bn0 != bn1);
    bn0 = bn1;
    EXPECT_TRUE(bn0 == bn1);
    //test for move assignment.
    BN bn2;
    EXPECT_TRUE(bn2 != bn1);
    bn2 = std::move(bn0);
    EXPECT_TRUE(bn0 != bn1);
    EXPECT_TRUE(bn2 == bn1);
}

TEST(BN, Add) {
    BN bn0;
    BN bn1("1100100", 2);
    BN bn2("1234", 10);
    BN bn3("ffff", 16);
    BN bn4(66869);
    BN bn5(133738);
    BN bn6(133748);
    bn0 = bn1 + bn2 + bn3;
    EXPECT_TRUE(bn0 == bn4);
    bn0 += bn1;
    bn0 += bn2;
    bn0 += bn3;
    EXPECT_TRUE(bn0 == bn5);
    bn0 = bn0 + 5;
    bn0 += 5;
    EXPECT_TRUE(bn0 == bn6);
    EXPECT_TRUE((BN::ONE + BN::MINUS_ONE) == BN::ZERO);
    EXPECT_TRUE((BN::ONE + BN::ZERO) == BN::ONE);
    EXPECT_TRUE((BN::ZERO + BN::ZERO) == BN::ZERO);
    EXPECT_TRUE((BN::TWO.Neg() + BN::TWO.Neg()) == BN::FOUR.Neg());
    EXPECT_TRUE((BN::FIVE.Neg() + BN::TWO) == BN::THREE.Neg());
}

TEST(BN, Sub) {
    BN bn0;
    BN bn1("1100100", 2);
    BN bn2("1234", 10);
    BN bn3("ffff", 16);
    BN bn4(-66669);
    BN bn5(-133538);
    BN bn6(-133548);
    bn0 = bn1 - bn2 - bn3;
    EXPECT_TRUE(bn0 == bn4);
    bn0 -= bn1;
    bn0 -= bn2;
    bn0 -= bn3;
    EXPECT_TRUE(bn0 == bn5);
    bn0 = bn0 - 5;
    bn0 -= 5;
    EXPECT_TRUE(bn0 == bn6);
    EXPECT_TRUE((BN::ONE - BN::ONE) == BN::ZERO);
    EXPECT_TRUE((BN::ONE - BN::ZERO) == BN::ONE);
    EXPECT_TRUE((BN::ZERO - BN::ZERO) == BN::ZERO);
    EXPECT_TRUE((BN::TWO.Neg() - BN::THREE.Neg()) == BN::ONE);
    EXPECT_TRUE((BN::TWO.Neg() - BN::ONE.Neg()) == BN::ONE.Neg());
}

TEST(BN, Mul) {
    BN bn0;
    BN bn1("1100100", 2);
    BN bn2("1234", 10);
    BN bn3("ffff", 16);
    BN bn4(8087019000);
    BN bn5("65399876306361000000", 10);
    BN bn6("653998763063610000000", 10);
    bn0 = bn1 * bn2 * bn3;
    EXPECT_TRUE(bn0 == bn4);
    bn0 *= bn1;
    bn0 *= bn2;
    bn0 *= bn3;
    EXPECT_TRUE(bn0 == bn5);
    bn0 = bn0 * 5;
    bn0 *= 2;
    EXPECT_TRUE(bn0 == bn6);
    EXPECT_TRUE((BN::ZERO * BN::FIVE) == BN::ZERO);
    EXPECT_TRUE((BN::ONE * BN::FIVE) == BN::FIVE);
    EXPECT_TRUE((BN::MINUS_ONE * BN::FIVE) == BN::FIVE.Neg());
    EXPECT_TRUE((BN::TWO.Neg() * BN::TWO.Neg()) == BN::FOUR);
    EXPECT_TRUE((BN::TWO.Neg() * BN::TWO) == BN::FOUR.Neg());
}

TEST(BN, Div) {
    BN bn0("65399876306361000101", 10);
    BN bn1("1100100", 2);
    BN bn2("1234", 10);
    BN bn3("ffff", 16);
    BN bn4("653998763063610001", 10);
    BN bn5(80870190);
    BN bn6(8087019);
    BN bn7(808701);
    bn0 = bn0 / bn1;
    EXPECT_TRUE(bn0 == bn4);
    bn0 /= bn1;
    bn0 /= bn2;
    bn0 /= bn3;
    EXPECT_TRUE(bn0 == bn5);
    bn0 = bn0 / 5;
    bn0 /= 2;
    EXPECT_TRUE(bn0 == bn6);
    bn0 = bn0 / 5;
    bn0 /= 2;
    EXPECT_TRUE(bn0 == bn7);
    EXPECT_TRUE((BN::FIVE / BN::ONE) == BN::FIVE);
    EXPECT_TRUE((BN::ONE.Neg() / BN::FIVE) == BN::ZERO);
    EXPECT_TRUE((BN::FIVE.Neg() / BN::TWO.Neg()) == BN::TWO);
    EXPECT_TRUE((BN::FIVE / BN::TWO.Neg()) == BN::TWO.Neg());
    EXPECT_TRUE((BN::ZERO / BN::FIVE) == BN::ZERO);
}

TEST(BN, Modular) {
    BN bn0("25", 10);
    BN bn1("101", 2);
    BN bn2("a", 16);
    BN bn3;
    bn3 = bn0 % bn1;
    EXPECT_TRUE(bn3 == BN::ZERO);
    bn3 = bn0 % 5;
    EXPECT_TRUE(bn3 == BN::ZERO);
    bn3 = bn0 % bn2;
    EXPECT_TRUE(bn3 == BN::FIVE);
    bn3 = bn0 % 10;
    EXPECT_TRUE(bn3 == BN::FIVE);

    bn0 = BN(-23);
    bn3 = bn0 % bn1;
    EXPECT_TRUE(bn3 == BN::TWO);
    bn3 = bn0 % 5;
    std::cout << bn3.Inspect() << std::endl;
    EXPECT_EQ(bn1, 5);
    //   std::cout << "%5: " << bn3.Inspect(10) << std::endl;
    EXPECT_EQ(bn3, BN::TWO);
    bn3 = bn0 % bn2;
    EXPECT_TRUE(bn3 == 7);
    bn3 = bn0 % 10;
    //   EXPECT_EQ(bn2, 10);
    //   std::cout << "%10: " << bn3.Inspect(10) << std::endl;
    EXPECT_EQ(bn3, 7);
}

TEST(BN, Shift) {
    BN bn0("1011", 2);
    BN bn1("10110000000000",2);
    BN bn2("10",2);
    EXPECT_TRUE((bn0 << 10) == bn1);
    EXPECT_TRUE((bn0 >> 2) == bn2);
    EXPECT_TRUE((bn0 >> 4) == BN::ZERO);
    EXPECT_TRUE((bn0 >> 10) == BN::ZERO);
    EXPECT_TRUE((bn0 <<= 10) == bn1);
    EXPECT_TRUE((bn0 >>= 12) == bn2);
    EXPECT_TRUE((bn0 >>= 2) == BN::ZERO);
    EXPECT_TRUE((bn0 >>= 10) == BN::ZERO);

    BN bn3("-1011", 2);
    BN bn4("-10110000000000",2);
    BN bn5("-10",2);
    EXPECT_TRUE((bn3 << 10) == bn4);
    EXPECT_TRUE((bn3 >> 2) == bn5);
    EXPECT_TRUE((bn3 >> 4) == BN::ZERO);
    EXPECT_TRUE((bn3 >> 10) == BN::ZERO);
    EXPECT_TRUE((bn3 <<= 10) == bn4);
    EXPECT_TRUE((bn3 >>= 12) == bn5);
    EXPECT_TRUE((bn3 >>= 2) == BN::ZERO);
    EXPECT_TRUE((bn3 >>= 10) == BN::ZERO);
}

TEST(BN, Comparison) {
    //for positive
    BN bn1(2568);
    BN bn2(2568);
    BN bn3(2569);
    BN bn4(2567);
    EXPECT_TRUE(bn1 == bn2);
    EXPECT_FALSE(bn1 != bn2);
    EXPECT_TRUE(bn1 >= bn2);
    EXPECT_TRUE(bn1 <= bn2);
    EXPECT_FALSE((bn1 > bn2) || (bn1 < bn2));
    EXPECT_TRUE((bn1 < bn3) && (bn3 > bn1));
    EXPECT_TRUE((bn4 < bn1) && (bn1 > bn4));
    EXPECT_TRUE((bn1 <= bn3) && (bn3 >= bn1));
    EXPECT_TRUE((bn4 <= bn1) && (bn1 >= bn4));
    EXPECT_FALSE((bn1 > bn3) || (bn3 < bn1));
    EXPECT_FALSE((bn1 >= bn3) || (bn3 <= bn1));
    EXPECT_FALSE((bn1 < bn4) || (bn4 > bn1));
    EXPECT_FALSE((bn1 <= bn4) || (bn4 >= bn1));
    EXPECT_FALSE(bn1 == bn3);
    EXPECT_TRUE(bn1 != bn3);
    EXPECT_TRUE(bn1 > 0);
    EXPECT_TRUE(bn1 >= 0);
    EXPECT_FALSE(bn1 < 0);
    EXPECT_FALSE(bn1 <= 0);
    EXPECT_TRUE(bn1 == 2568);
    EXPECT_FALSE(bn1 != 2568);
    EXPECT_TRUE(bn1 >= 2568);
    EXPECT_TRUE(bn1 <= 2568);
    EXPECT_TRUE(bn1 > 2567);
    EXPECT_TRUE(bn1 < 2569);
    EXPECT_TRUE(bn1 >= 2567);
    EXPECT_TRUE(bn1 <= 2569);
    //for negative
    BN bn5("-abc",16);
    BN bn6("-ABC", 16);
    BN bn7("-aba", 16);
    BN bn8("-abd", 16);
    EXPECT_TRUE(bn5 == bn6);
    EXPECT_FALSE(bn5 != bn6);
    EXPECT_TRUE(bn5 >= bn6);
    EXPECT_TRUE(bn5 <= bn6);
    EXPECT_FALSE((bn5 > bn6) || (bn5 < bn6));
    EXPECT_TRUE((bn5 < bn7) && (bn7 > bn5));
    EXPECT_TRUE((bn8 < bn5) && (bn5 > bn8));
    EXPECT_TRUE((bn5 <= bn7) && (bn7 >= bn5));
    EXPECT_TRUE((bn8 <= bn5) && (bn5 >= bn8));
    EXPECT_FALSE((bn5 > bn7) || (bn7 < bn5));
    EXPECT_FALSE((bn5 >= bn7) || (bn7 <= bn5));
    EXPECT_FALSE((bn5 < bn8) || (bn8 > bn5));
    EXPECT_FALSE((bn5 <= bn8) || (bn8 >= bn5));
    EXPECT_FALSE(bn5 == bn7);
    EXPECT_TRUE(bn5 != bn7);
    EXPECT_TRUE(bn5 < 0);
    EXPECT_TRUE(bn5 <= 0);
    EXPECT_FALSE(bn5 > 0);
    EXPECT_FALSE(bn5 >= 0);
    EXPECT_TRUE(bn5 == -2748);
    EXPECT_FALSE(bn5 != -2748);
    EXPECT_TRUE(bn5 >= -2748);
    EXPECT_TRUE(bn5 <= -2748);
    EXPECT_TRUE(bn5 > -2749);
    EXPECT_TRUE(bn5 < -2746);
    EXPECT_TRUE(bn5 >= -2749);
    EXPECT_TRUE(bn5 <= -2746);
    //mix
    EXPECT_TRUE((bn1 > bn5) && (bn5 < bn1));
    EXPECT_TRUE((bn1 >= bn5) && (bn5 <= bn1));
    EXPECT_TRUE(bn1 != bn5);
    EXPECT_FALSE(bn1 == bn5);
    EXPECT_TRUE(bn1 > -2748);
    EXPECT_TRUE(bn5 < 2568);
    EXPECT_TRUE(bn1 >= -2748);
    EXPECT_TRUE(bn5 <= 2568);
    EXPECT_TRUE(bn1 != -2748);
    EXPECT_FALSE(bn1 == -2748);
}

TEST(BN, NumberTheory) {
    BN bn0;
    BN bn1(10);
    BN bn2(-10);
    EXPECT_TRUE(bn1.Neg() == bn2);
    EXPECT_TRUE(bn2.Neg() == bn1);
    EXPECT_TRUE(bn0.Neg() == bn0);

    BN bn3(3);
    BN bn4, bn5;
    bn1.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 3) && (bn5 == 1));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == -3) && (bn5 == -1));
    bn3 = BN(-3);
    bn1.Div(bn3,bn4,bn5);
    EXPECT_TRUE((bn4 == -3) && (bn5 == 1));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 3) && (bn5 == -1));

    bn1 = BN(20);
    bn2 = BN(-20);
    bn3 = BN(7);
    bn1.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 2) && (bn5 == 6));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == -2) && (bn5 == -6));
    bn3 = BN(-7);
    bn1.Div(bn3,bn4,bn5);
    EXPECT_TRUE((bn4 == -2) && (bn5 == 6));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 2) && (bn5 == -6));

    bn1 = BN(30);
    bn2 = BN(-30);
    bn3 = BN(6);
    bn1.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 5) && (bn5 == 0));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == -5) && (bn5 == 0));
    bn3 = BN(-6);
    bn1.Div(bn3,bn4,bn5);
    EXPECT_TRUE((bn4 == -5) && (bn5 == 0));
    bn2.Div(bn3, bn4, bn5);
    EXPECT_TRUE((bn4 == 5) && (bn5 == 0));

    BN bn6(7);
    BN bn7(2);
    BN bn8(3);
    EXPECT_EQ(bn7.InvM(bn6), 4);
    EXPECT_EQ(bn8.InvM(bn6), 5);
    bn6 = BN(11);
    EXPECT_EQ(bn7.InvM(bn6), 6);
    EXPECT_EQ(bn8.InvM(bn6), 4);

    bn6 = BN(7);
    EXPECT_EQ(bn7.PowM(bn8,bn6), 1);
    EXPECT_EQ(bn7.PowM(bn7,bn6), 4);
    EXPECT_EQ(bn8.PowM(bn7,bn6), 2);
    EXPECT_EQ(bn8.PowM(bn8,bn6), 6);

    bn6 = BN(23);
    EXPECT_TRUE(bn7.ExistSqrtM(bn6));
    EXPECT_TRUE(bn7.SqrtM(bn6) == 5 || bn7.SqrtM(bn6) == 18);
    bn6 = BN(13);
    EXPECT_TRUE(bn8.ExistSqrtM(bn6));
    EXPECT_TRUE(bn8.SqrtM(bn6) == 4 ||bn8.SqrtM(bn6) == 9);
    bn6 = BN(11);
    EXPECT_FALSE(bn7.ExistSqrtM(bn6));

    bn6 = BN(7);
    EXPECT_TRUE(bn6.IsProbablyPrime());
    bn6 = BN(2147483647);
    EXPECT_TRUE(bn6.IsProbablyPrime());
    bn6 =  BN::FromDecStr("3512361716805789371972727939883643101583447981968520"
                          "328116222065795410830354167025485897169128481068329654077646734548662444"
                          "384264600983851903304370332254379348431475618118443515097594013924630541"
                          "0828726731670875346026456911796687116940339837750972042560711485424581228"
                          "15112287827804817008054571967569811098943958115474043611129903319499487179"
                          "31275315698239060479759467211010927996811642694668143998681714908245060366"
                          "776555066332127329304716050935303286792734592049624692299978648654921120227"
                          "652227236744907852210908978855731702859500827419174748928577397977510254103"
                          "5592329871004023280977348435038643994502879226281");
    EXPECT_FALSE(bn6.IsProbablyPrime());
    bn6 = BN::FromDecStr("531137992816767098689588206552468627329593117727031923199444138200403559860852242739162502265229285668889329486246501015346579337652707239409519978766587351943831270835393219031728127");
    EXPECT_TRUE(bn6.IsProbablyPrime());

    BN bn9(45);
    BN bn10(63);
    EXPECT_TRUE(bn9.Gcd(bn10) == 9);
    EXPECT_TRUE(bn9.Lcm(bn10) == 315);
    bn9 = BN(7);
    bn10 = BN(70);
    EXPECT_TRUE(bn9.Gcd(bn10) == 7);
    EXPECT_TRUE(bn9.Lcm(bn10) == 70);
    bn9 = BN(1);
    bn10 = BN(4);
    EXPECT_TRUE(bn9.Gcd(bn10) == 1);
    EXPECT_TRUE(bn9.Lcm(bn10) == 4);
}

TEST(BN, Auxiliary) {
    BN bn0;
    EXPECT_EQ(bn0.BitLength(), 0);
    EXPECT_EQ(bn0.ByteLength(), 0);
    EXPECT_EQ(bn0.IsNeg(), false);
    EXPECT_EQ(bn0.IsZero(), true);
    EXPECT_EQ(bn0.IsOdd(), false);
    EXPECT_EQ(bn0.IsEven(), true);
    bn0 = BN::FromDecStr("0");
    EXPECT_EQ(bn0.BitLength(), 0);
    EXPECT_EQ(bn0.ByteLength(), 0);
    EXPECT_EQ(bn0.IsNeg(), false);
    EXPECT_EQ(bn0.IsZero(), true);
    EXPECT_EQ(bn0.IsOdd(), false);
    EXPECT_EQ(bn0.IsEven(), true);
    BN bn1 = BN::FromDecStr("1");
    EXPECT_EQ(bn1.BitLength(), 1);
    EXPECT_EQ(bn1.ByteLength(), 1);
    EXPECT_EQ(bn1.IsNeg(), false);
    EXPECT_EQ(bn1.IsZero(), false);
    EXPECT_EQ(bn1.IsOdd(), true);
    EXPECT_EQ(bn1.IsEven(), false);
    BN bn2 = BN::FromDecStr("-258");
    EXPECT_EQ(bn2.BitLength(), 9);
    EXPECT_EQ(bn2.ByteLength(), 2);
    EXPECT_EQ(bn2.IsNeg(), true);
    EXPECT_EQ(bn2.IsZero(), false);
    EXPECT_EQ(bn2.IsOdd(), false);
    EXPECT_EQ(bn2.IsEven(), true);

    EXPECT_EQ(BN::Max(bn0, bn1), bn1);
    EXPECT_EQ(BN::Min(bn0,bn1), bn0);
    EXPECT_EQ(BN::Max(bn1, bn2), bn1);
    EXPECT_EQ(BN::Min(bn1,bn2), bn2);

    BN::Swap(bn1, bn2);
    EXPECT_EQ(bn1, -258);
    EXPECT_EQ(bn2, 1);
    BN::Swap(bn2, bn0);
    EXPECT_EQ(bn0, 1);
    EXPECT_EQ(bn2, 0);

    BN bn3("01111111",2);
    EXPECT_EQ(bn3.Inspect(), "7F");
    EXPECT_FALSE(bn3.IsBitSet(7));
    bn3.SetBit(7);
    EXPECT_EQ(bn3.Inspect(), "FF");
    EXPECT_TRUE(bn3.IsBitSet(7));
    EXPECT_EQ(bn3, 255);
    bn3.ClearBit(0);
    EXPECT_EQ(bn3.Inspect(), "FE");
    EXPECT_FALSE(bn3.IsBitSet(0));
    EXPECT_EQ(bn3, 254);
}

TEST(BN, StringConversion) {
    //bn0: 1111 1111 1111 1111
    BN bn0("1111111111111111",2);
    std::string str_16 = "ffff";
    std::string str_10 = "65535";
    BN bn1 = BN::FromHexStr("ffff");
    BN bn2 = BN::FromHexStr(str_16);
    BN bn3 = BN::FromDecStr("65535");
    BN bn4 = BN::FromDecStr(str_10);
    EXPECT_EQ(bn0, bn1);
    EXPECT_EQ(bn0, bn2);
    EXPECT_EQ(bn0, bn3);
    EXPECT_EQ(bn0, bn4);
    //bn5: 101 0000 1111, bn6: 01 0111 0011
    BN bn5("10100001111", 2);
    BN bn6("0101110011",2);
    bn5.ToHexStr(str_16);
    bn5.ToDecStr(str_10);
    EXPECT_EQ(str_16, "050F");
    EXPECT_EQ(str_10, "1295");
    bn6.ToHexStr(str_16);
    bn6.ToDecStr(str_10);
    EXPECT_EQ(str_16, "0173");
    EXPECT_EQ(str_10, "371");
}

TEST(BN, ByteConversion) {
    std::string str_buf = "cba";
    uint8_t ch_buf[10];
    ch_buf[0] = 'c';
    ch_buf[1] = 'b';
    ch_buf[2] = 'a';
    BN bn_big_endian("636261", 16);
    BN bn_little_endian("616263", 16);
    BN bn1 = BN::FromBytesBE(ch_buf, 3);
    BN bn2 = BN::FromBytesBE(str_buf);
    BN bn3 = BN::FromBytesLE(ch_buf,3);
    BN bn4 = BN::FromBytesLE(str_buf);
    EXPECT_EQ(bn1, bn_big_endian);
    EXPECT_EQ(bn2, bn_big_endian);
    EXPECT_EQ(bn3, bn_little_endian);
    EXPECT_EQ(bn4, bn_little_endian);
    BN bn5("0100001001000100", 2);
    std::string str_big_endian = "";
    std::string str_little_endian = "";
    bn5.ToBytesBE(str_big_endian);
    bn5.ToBytesLE(str_little_endian);
    EXPECT_EQ(str_big_endian, "BD");
    EXPECT_EQ(str_little_endian, "DB");
    BN bn6("1011110011000111", 2);
    uint8_t expected_big_endian[2] = { 0xbc, 0xc7};
    uint8_t expected_little_endian[2] = { 0xc7, 0xbc};
    bn6.ToBytesBE(str_big_endian);
    bn6.ToBytesLE(str_little_endian);
    std::cout << "str_big_endian: " << str_big_endian << std::endl;
    std::cout << "str_little_endian: " << str_little_endian << std::endl;
    for(int i = 0; i < 2; i++) {
        EXPECT_EQ((uint8_t)str_big_endian[i], expected_big_endian[i]);
        EXPECT_EQ((uint8_t)str_little_endian[i], expected_little_endian[i]);
    }

    BN bn32("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16);
    uint8_t expected_ch_big[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                   0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t expected_ch_little[32] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
                                      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
    uint8_t ch_big_endian[32], ch_little_endian[32];
    bn32.ToBytes32BE(str_big_endian);
    bn32.ToBytes32LE(str_little_endian);
    bn32.ToBytes32BE(ch_big_endian);
    bn32.ToBytes32LE(ch_little_endian);
    for(int i = 0; i < 32; i++) {
        EXPECT_EQ((uint8_t)str_big_endian[i], expected_ch_big[i]);
        EXPECT_EQ((uint8_t)str_little_endian[i], expected_ch_little[i]);
        EXPECT_EQ(ch_big_endian[i], expected_ch_big[i]);
        EXPECT_EQ(ch_little_endian[i], expected_ch_little[i]);
    }
}

TEST(BN, ToStringFromString) {
    BN n1 = BN::FromDecStr("24785187341154544549914104546227");
    BN n2 = BN::FromHexStr("FFFFFFFFFFFFFFFF");
    std::string s1, s2;

    n1.ToDecStr(s1);
    n2.ToHexStr(s2);

    EXPECT_TRUE(s1.compare("24785187341154544549914104546227") == 0);
    EXPECT_TRUE(s2.compare("FFFFFFFFFFFFFFFF") == 0);
}

TEST(BN, ToBytesFromBytes) {
    uint8_t ch[10];
    ch[0] = 0x01;
    ch[1] = 0x02;
    BN n1 = BN::FromBytesBE(ch, 2);
    BN n2 = BN::FromBytesLE(ch, 2);
    std::string s1, s2;

    n1.ToDecStr(s1);
    n2.ToDecStr(s2);

    EXPECT_TRUE(s1.compare("258") == 0);
    EXPECT_TRUE(s2.compare("513") == 0);

    std::string ns1, ns2;
    n1.ToBytesBE(ns1);
    n2.ToBytesBE(ns2);
    EXPECT_EQ(ns1.at(0), 0x01);
    EXPECT_EQ(ns1.at(1), 0x02);
    EXPECT_EQ(ns1.at(0), 0x01);
    EXPECT_EQ(ns1.at(1), 0x02);
}

TEST(BN, ToBytes32FromBytes32)
{
    uint8_t num1[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    uint8_t num2[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t num3[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00};
    uint8_t num4[33] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21};
    BN n1 = BN::FromBytesBE(num1, 32);
    uint8_t buf32BE[32];
    uint8_t buf32LE[32];
    n1.ToBytes32BE(buf32BE);
    n1.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num1[i], buf32BE[i]);
        EXPECT_EQ(num1[i], buf32LE[31 - i]);
    }
    BN n2 = BN::FromBytesBE(num2, 32);
    BN expected_n2 = BN::FromBytesBE(num2 + 1, 32 - 1);
    EXPECT_TRUE(n2 == expected_n2);
    n2.ToBytes32BE(buf32BE);
    n2.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num2[i], buf32BE[i]);
        EXPECT_EQ(num2[i], buf32LE[31 - i]);
    }
    BN n3 = BN::FromBytesLE(num3, 32);
    BN expected_n3 = BN::FromBytesLE(num3, 32 - 1);
    EXPECT_TRUE(n3 == expected_n3);
    n3.ToBytes32BE(buf32BE);
    n3.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num3[i], buf32LE[i]);
        EXPECT_EQ(num3[i], buf32BE[31 - i]);
    }
    BN n4 = BN::FromBytesBE(num4, 33);
    n4.ToBytes32BE(buf32BE);
    n4.ToBytes32LE(buf32LE);
    for(int i = 0; i < 32; ++i){
        EXPECT_EQ(num4[i + 1], buf32BE[i]);
        EXPECT_EQ(num4[i + 1], buf32LE[31 - i]);
    }
}

bool isRootM(BN &a, BN &b, BN &m){
    return (a == b) || (a + b == m);
}

TEST(BN, SquareRootModuloP)
{
    BN p0(5);
    BN n0(0);
    BN r0 = n0.SqrtM(p0);
    EXPECT_TRUE(r0 == 0);

    BN p1(5);
    BN n1(2);
    EXPECT_FALSE( n1.ExistSqrtM(p1) );
    try {
        BN r1 = n1.SqrtM(p1);
    }catch (const LocatedException &e) {
        std::cout << e.detail() << std::endl;
    }

    BN p2(5);
    BN n2(4);
    BN r2;
    r2 = n2.SqrtM(p2);
    std::cout << r2.Inspect() << std::endl;
    EXPECT_TRUE(r2 == 3);

    BN p3 = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    BN r3_0("ffffffff000000010000fffff0000000100000000000", 16);
    BN r3_1("ffffffff000000010000fffff0000000100000000001", 16);
    BN r3_2("ffffffff000000010000fffff0000000100000000002", 16);
    BN r3_3("ffffffff000000010000fffff0000000100000000003", 16);
    BN r3_4("ffffffff000000010000fffff0000000100000000004", 16);
    BN r3_5("ffffffff000000010000fffff0000000100000000005", 16);
    n2 = (r3_0 * r3_0) % p3;
    BN ret3_0 = n2.SqrtM(p3);
    n2 = (r3_1 * r3_1) % p3;
    BN ret3_1 = n2.SqrtM(p3);
    n2 = (r3_2 * r3_2) % p3;
    BN ret3_2 = n2.SqrtM(p3);
    n2 = (r3_3 * r3_3) % p3;
    BN ret3_3 = n2.SqrtM(p3);
    n2 = (r3_4 * r3_4) % p3;
    BN ret3_4 = n2.SqrtM(p3);
    n2 = (r3_5 * r3_5) % p3;
    BN ret3_5 = n2.SqrtM(p3);
    EXPECT_TRUE(isRootM(r3_0, ret3_0, p3));
    EXPECT_TRUE(isRootM(r3_1, ret3_1, p3));
    EXPECT_TRUE(isRootM(r3_2, ret3_2, p3));
    EXPECT_TRUE(isRootM(r3_3, ret3_3, p3));
    EXPECT_TRUE(isRootM(r3_4, ret3_4, p3));
    EXPECT_TRUE(isRootM(r3_5, ret3_5, p3));
    //EXPECT_TRUE(eqM(r3_0 == (ret3_0.Neg() % p3) );
    //EXPECT_TRUE(r3_1 == ret3_1);
    //EXPECT_TRUE(r3_2 == ret3_2);
    //EXPECT_TRUE(r3_3 == ret3_3);
    //EXPECT_TRUE(r3_4 == ret3_4);
    //EXPECT_TRUE(r3_5 == ret3_5);

    //BN p3 = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    //BN r3_0("ffffffff000000010000fffff0000000100000000000", 16);
    //BN r3_1("ffffffff000000010000fffff0000000100000000001", 16);
    //BN r3_2("ffffffff000000010000fffff0000000100000000002", 16);
    //BN r3_3("ffffffff000000010000fffff0000000100000000003", 16);
    //BN r3_4("ffffffff000000010000fffff0000000100000000004", 16);
    //BN r3_5("ffffffff000000010000fffff0000000100000000005", 16);
    //n2 = (r3_0 * r3_0) % p3;
    //BN ret3_0 = n2.SqrtM(p3);
    //n2 = (r3_1 * r3_1) % p3;
    //BN ret3_1 = n2.SqrtM(p3);
    //n2 = (r3_2 * r3_2) % p3;
    //BN ret3_2 = n2.SqrtM(p3);
    //n2 = (r3_3 * r3_3) % p3;
    //BN ret3_3 = n2.SqrtM(p3);
    //n2 = (r3_4 * r3_4) % p3;
    //BN ret3_4 = n2.SqrtM(p3);
    //n2 = (r3_5 * r3_5) % p3;
    //BN ret3_5 = n2.SqrtM(p3);
    //EXPECT_TRUE(r3_0 == ret3_0);
    //EXPECT_TRUE(r3_1 == ret3_1);
    //EXPECT_TRUE(r3_2 == ret3_2);
    //EXPECT_TRUE(r3_3 == ret3_3);
    //EXPECT_TRUE(r3_4 == ret3_4);
    //EXPECT_TRUE(r3_5 == ret3_5);

    //BN p4(11);
    //BN n4(7);
    //BN r4 = n2.SqrtM(p1);
    //EXPECT_TRUE(r4 == 3);
}

TEST(BN, SquareRootModuloP_More)
{
    BN p = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    for(int i = 0; i < 100; ++i){
        BN r = safeheron::rand::RandomBNLt(p);
        BN n = (r * r) % p;
        BN ret = n.SqrtM(p);
        EXPECT_TRUE(isRootM(r, ret, p));
    }
}

TEST(BN, SelfAssign)
{
    BN p = BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff") ;
    std::string str;
    p.ToHexStr(str);
    std::cout << "Before self-assignment: " << str << std::endl;
    p = std::move(p);
    p.ToHexStr(str);
    std::cout << "After self-assignment: " << str << std::endl;
}

TEST(BN, FromAndTo)
{
    // DON'T SUPPORT convert "" to BIGNUM!!!
    // expect a/b/c are Zero
    //BN a("", 2);
    //BN b("", 10);
    //BN c("", 16);
    //EXPECT_TRUE(a.IsZero());
    //EXPECT_TRUE(b.IsZero());
    //EXPECT_TRUE(c.IsZero());

    // expect a/b/c are Zero
    std::string str;
    uint8_t buff[256] = {0};
    BN d1 = BN::FromHexStr("0");
    BN d2 = BN::FromDecStr("0");
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());
    d1 = BN::FromBytesBE(str);
    d2 = BN::FromBytesLE(str);
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());
    d1 = BN::FromBytesBE(buff, 0);
    d2 = BN::FromBytesLE(buff, 0);
    EXPECT_TRUE(d1.IsZero());
    EXPECT_TRUE(d2.IsZero());

    // BigNum Zero to string
    BN n;
    std::string s1,s2;
    n.ToHexStr(s1);
    n.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("0") == 0);
    EXPECT_TRUE(s2.compare("0") == 0);
    n.ToBytesBE(s1);
    n.ToBytesLE(s2);
    EXPECT_TRUE(s1.compare("") == 0);   //TODO:
    EXPECT_TRUE(s2.compare("") == 0);   //TODO:

    // BigNum Zero to buff
    uint8_t buff32[32] = {0};
    n.ToBytes32BE(buff);
    EXPECT_TRUE(memcmp(buff, buff32, 32) == 0);
    n.ToBytes32LE(buff);
    EXPECT_TRUE(memcmp(buff, buff32, 32) == 0);

    BN m(5);
    m.ToHexStr(s1);
    m.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("05") == 0);
    EXPECT_TRUE(s2.compare("5") == 0);
    m = BN::FromHexStr("5");
    m.ToHexStr(s1);
    EXPECT_TRUE(s1.compare("05") == 0);

    BN p(-2);
    p.ToHexStr(s1);
    p.ToDecStr(s2);
    EXPECT_TRUE(s1.compare("-02") == 0);
    EXPECT_TRUE(s2.compare("-2") == 0);
    p = BN::FromDecStr("-0");
    EXPECT_TRUE(p.IsZero());

}

TEST(BN, BitOperation)
{
    uint8_t num1[3] = {0x01, 0x02, 0x03};
    BN n1 = BN::FromBytesBE(num1, 3);
    EXPECT_TRUE(n1.IsBitSet(0));
    EXPECT_TRUE(n1.IsBitSet(1));
    EXPECT_TRUE(!n1.IsBitSet(2));
    EXPECT_TRUE(n1.IsBitSet(9));
    EXPECT_TRUE(n1.IsBitSet(16));
    EXPECT_TRUE(n1 == 0x010203);
    n1.SetBit(23);
    EXPECT_TRUE(n1 == 0x810203);
    n1.SetBit(7);
    EXPECT_TRUE(n1 == 0x810283);
    n1.ClearBit(9);
    EXPECT_TRUE(n1 == 0x810083);
}

TEST(BN, ModPow)
{
    //BN n11 = BN::FromHexStr("3512361716805789371972727939883643101583447981968520328116222065795410830354167025485897169128481068329654077646734548662444384264600983851903304370332254379348431475618118443515097594013924630541082872673167087534602645691179668711694033983775097204256071148542458122815112287827804817008054571967569811098943958115474043611129903319499487179312753156982390604797594672110109279968116426946681439986817149082450603667765550663321273293047160509353032867927345920496246922999786486549211202276522272367449078522109089788557317028595008274191747489285773979775102541035592329871004023280977348435038643994502879226281");
    //BN pp1 = BN::FromDecStr("24785187341154544549914104546227324477849397927398564865898843147322410450159242714370313726215895344220422746105653910669926029449459443135240985638132813206618427011656415731288349869320099645008300932936995561385777390730121084071260567710340592802651082340376366434798431644732948435115566808067213452460824745589204954083798251054081876658612393182807087164285433664045394356387935544555343059651032295512441123006645668258731185928418616367925541996626300252413082259164698109375439746033443057802058077833685231311051193530557877051836264709759220533097861910127780566282488800845776390118872368439248528368887");
    //BN pp2 = BN::FromDecStr("24785187341154544549914104546227324477849397927398564865898843147322410450159242714370313726215895344220422746105653910669926029449459443135240985638132813206618427011656415731288349869320099645008300932936995561385777390730121084071260567710340592802651082340376366434798431644732948435115566808067213452460824745589204954083798251054081876658612393182807087164285433664045394356387935544555343059651032295512441123006645668258731185928418616367925541996626300252413082259164698109375439746033443057802058077833685231311051193530557877051836264709759220533097861910127780566282488800845776390118872368439248528368887");
    BN n11 = BN::FromHexStr("351");
    BN pp1 = BN::FromDecStr("247");
    BN pp2 = BN::FromDecStr("247");
    clock_t start, end;
    start = clock();
    BN ret;
    for(int j = 0; j < 5; j ++){
        ret = n11.PowM(pp1, pp2);
    }
    end = clock();
    std::cout << double(end - start)/CLOCKS_PER_SEC << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
