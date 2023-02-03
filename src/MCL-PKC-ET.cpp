// g++ -o MCL-PKC-ET MCL-PKC-ET.cpp -L. -lpbc -lgmp -lssl -lcrypto
// ./MCL-PKC-ET ../params/e256.param
/**MCL-PKC-ET.cpp**/

#include "../include/MCL-PKC-ET.h"
#include <iostream>
#include <cstring>
#include <openssl/sha.h>
#include <fstream>
#include <string>
#include <time.h>
#include <queue>

using namespace std;

#define ITERCNT 10
#define TESTCNT 1000

MCL_PKC_ET::MCL_PKC_ET(/*int lambda = 80*/)
{
    this->init();
    flag = false;
}

MCL_PKC_ET::MCL_PKC_ET(int argc, char **argv)
{
    pbc_demo_pairing_init(pairing, argc, argv);
    this->init();
}

MCL_PKC_ET::~MCL_PKC_ET()
{
    this->clear();
}

void MCL_PKC_ET::init(){
    element_init_GT(g, pairing);
    element_init_G1(P, pairing);
    element_init_G1(P1, pairing);
    element_init_G1(P2, pairing);
    element_init_Zr(s1, pairing);
    element_init_Zr(s2, pairing);

    element_random(P);
    element_random(s1);
    element_random(s2);

    element_mul_zn(P1, P, s1);
    element_mul_zn(P2, P, s2);
    element_pairing(g, P, P);

    lenG1 = pairing_length_in_bytes_G1(pairing);
    lenGT = pairing_length_in_bytes_GT(pairing);
    lenZr = pairing_length_in_bytes_Zr(pairing);

}
void MCL_PKC_ET::clear()
{
    element_clear(s1);
    element_clear(s2);
    element_clear(g);
    element_clear(P);
    element_clear(P1);
    element_clear(P2);
    pairing_clear(pairing);
}

unsigned char *MCL_PKC_ET::Extract_Private_Value()
{
    element_t xID;
    unsigned char *strXID = new unsigned char[lenZr];

    memset(strXID, 0x00, lenZr);

    element_init_Zr(xID, pairing);
    element_random(xID);

    element_to_bytes(strXID, xID);

    return strXID;
}

KEY *MCL_PKC_ET::Extract_Partial_Private_Key(const unsigned char *ID)
{
    unsigned char *HashID = new unsigned char[SHA256_DIGEST_LENGTH];
    KEY *dk = new KEY;
    element_t HID;
    element_t dk1, dk2;
    element_t tmp1, tmp2;

    dk->key1 = new unsigned char[lenG1];
    dk->key2 = new unsigned char[lenG1];

    memset(dk->key1, 0x00, lenG1);
    memset(dk->key2, 0x00, lenG1);

    element_init_Zr(HID, pairing);
    element_init_Zr(tmp1, pairing);
    element_init_Zr(tmp2, pairing);

    element_init_G1(dk1, pairing);
    element_init_G1(dk2, pairing);

    H1(ID, ID_SPACE, HashID, SHA256_DIGEST_LENGTH);
    element_from_hash(HID, HashID, SHA256_DIGEST_LENGTH);

    element_add(tmp1, HID, s1);
    element_invert(tmp1, tmp1);
    element_mul_zn(dk1, P, tmp1);

    element_add(tmp2, HID, s2);
    element_invert(tmp2, tmp2);
    element_mul_zn(dk2, P, tmp2);

    element_to_bytes(dk->key1, dk1);
    element_to_bytes(dk->key2, dk2);

    element_clear(HID);
    element_clear(dk1);
    element_clear(dk2);
    element_clear(tmp1);
    element_clear(tmp2);

    delete[] HashID;

    return dk;
}
KEY *MCL_PKC_ET::Extract_Private_Key(const KEY dk, const unsigned char *x, const PK pk)
{
    KEY *sk = new KEY;
    element_t dk1, dk2;
    element_t sk1, sk2;
    element_t h1, h2;
    element_t xID;
    element_t tmp1, tmp2;

    unsigned char *hash1 = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *hash2 = new unsigned char[SHA256_DIGEST_LENGTH];

    sk->key1 = new unsigned char[lenG1];
    sk->key2 = new unsigned char[lenG1];

    memset(sk->key1, 0x00, lenG1);
    memset(sk->key2, 0x00, lenG1);

    element_init_G1(dk1, pairing);
    element_init_G1(dk2, pairing);
    element_init_G1(sk1, pairing);
    element_init_G1(sk2, pairing);

    element_init_Zr(xID, pairing);
    element_init_Zr(h1, pairing);
    element_init_Zr(h2, pairing);
    element_init_Zr(tmp1, pairing);
    element_init_Zr(tmp2, pairing);

    element_from_bytes(xID, (unsigned char *)x);
    element_from_bytes(dk1, (unsigned char *)dk.key1);
    element_from_bytes(dk2, (unsigned char *)dk.key2);

    H2(pk.pk1, lenG1, hash1, SHA256_DIGEST_LENGTH);
    H2(pk.pk2, lenG1, hash2, SHA256_DIGEST_LENGTH);

    element_from_hash(h1, hash1, SHA256_DIGEST_LENGTH);
    element_from_hash(h2, hash2, SHA256_DIGEST_LENGTH);

    element_add(tmp1, xID, h1);
    element_invert(tmp1, tmp1);
    element_mul_zn(sk1, dk1, tmp1);

    element_add(tmp2, xID, h2);
    element_invert(tmp2, tmp2);
    element_mul_zn(sk2, dk2, tmp2);

    element_to_bytes(sk->key1, sk1);
    element_to_bytes(sk->key2, sk2);

    element_clear(dk1);
    element_clear(dk2);
    element_clear(sk1);
    element_clear(sk2);
    element_clear(xID);
    element_clear(h1);
    element_clear(h2);
    element_clear(tmp1);
    element_clear(tmp2);

    return sk;
}
PK *MCL_PKC_ET::Extract_Public_Key(const unsigned char *x, unsigned char *ID)
{
    PK *pk = new PK;
    element_t pk1, pk2, pk3;
    element_t xID, HID;
    element_t tmp;

    unsigned char *HashID = new unsigned char[SHA256_DIGEST_LENGTH];

    pk->pk1 = new unsigned char[lenG1];
    pk->pk2 = new unsigned char[lenG1];
    pk->pk3 = new unsigned char[lenG1];

    memset(pk->pk1, 0x00, lenG1);
    memset(pk->pk2, 0x00, lenG1);
    memset(pk->pk3, 0x00, lenG1);

    element_init_G1(pk1, pairing);
    element_init_G1(pk2, pairing);
    element_init_G1(pk3, pairing);

    element_init_Zr(xID, pairing);
    element_init_Zr(HID, pairing);
    element_init_G1(tmp, pairing);

    element_from_bytes(xID, (unsigned char *)x);
    H1(ID, ID_SPACE, HashID, SHA256_DIGEST_LENGTH);
    element_from_hash(HID, HashID, SHA256_DIGEST_LENGTH);

    element_mul_zn(tmp, P, HID); // tmp = P * HID

    element_add(pk1, tmp, P1); // pk1 = P * HID + Ppub
    element_mul_zn(pk1, pk1, xID); // pk1 = xID(P * HID + Ppub)

    element_add(pk2, tmp, P2); // pk2 = P * HID + P'pub
    element_mul_zn(pk2, pk2, xID); // pk2 = xID(P * HID + P'pub)

    element_mul_zn(pk3, P, xID); // pk3 = P * xID
    

    element_to_bytes(pk->pk1, pk1);
    element_to_bytes(pk->pk2, pk2);
    element_to_bytes(pk->pk3, pk3);

    element_clear(pk1);
    element_clear(pk2);
    element_clear(pk3);
    element_clear(xID);
    element_clear(HID);
    element_clear(tmp);

    delete[] HashID;

    return pk;
}

void MCL_PKC_ET::Verify_Public_Key(const PK pk)
{
    element_t LHS, RHS;
    element_t tmp1, tmp2;
    element_t pk1, pk2, pk3;

    element_init_G1(pk1, pairing);
    element_init_G1(pk2, pairing);
    element_init_G1(pk3, pairing);
    
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);

    element_init_GT(LHS, pairing);
    element_init_GT(RHS, pairing);

    
    element_from_bytes(pk1, (unsigned char *)pk.pk1);
    element_from_bytes(pk2, (unsigned char *)pk.pk2);
    element_from_bytes(pk3, (unsigned char *)pk.pk3);

    element_sub(tmp1, pk1, pk2); // tmp1 = pk1 - pk2
    element_sub(tmp2, P1, P2); // tmp2 = P1 - P2

    element_pairing(LHS, tmp1, P); // LHS = e(tmp1, P)
    element_pairing(RHS, tmp2, pk3); // RHS = e(tmp2, pk3)

    if(element_cmp(LHS, RHS))
    {
        printf("Invalid Public Key\n");
        abort();
    }
    else
        flag = true;

}

CIPHER *MCL_PKC_ET::Encrypt(const unsigned char *ID, const PK pk, const unsigned char *M)
{
    if(flag == false)
        Verify_Public_Key(pk);
    
    CIPHER *C = new CIPHER;

    element_t r1, r2;
    element_t C1, C2, C4;
    element_t C3_Pair;
    element_t C4_Pair, C4_Left;
    element_t h1, h2;
    element_t pk1, pk2;
    element_t HID, m;
    element_t tmp;
    
    unsigned char *hashID = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *hashM = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *hash1 = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *hash2 = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *strC3_Pair = new unsigned char[lenGT];
    unsigned char *strC3_Left = new unsigned char[lenG1 + lenZr];
    unsigned char *strC3_Right = new unsigned char[lenGT + lenZr];
    unsigned char *strC3_Hash = new unsigned char[lenG1 + lenZr];
    unsigned char *strC4_Pair = new unsigned char[lenGT];
    unsigned char *strC4_Left = new unsigned char[lenZr];
    unsigned char *strC4_Right = new unsigned char[lenZr];
    unsigned char *strR2 = new unsigned char[lenZr];
    
    C->C1 = new unsigned char[lenG1];
    C->C2 = new unsigned char[lenG1];
    C->C3 = new unsigned char[lenG1 + lenZr];
    C->C4 = new unsigned char[lenZr];

    memset(C->C1, 0x00, lenG1);
    memset(C->C2, 0x00, lenG1);
    memset(C->C3, 0x00, lenG1 + lenZr);
    memset(strC3_Left, 0x00, lenG1 + lenZr);
    memset(strC3_Pair, 0x00, lenGT);
    memset(strC4_Pair, 0x00, lenGT);
    memset(strR2, 0x00, lenZr);
    
    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_init_Zr(HID, pairing);
    element_init_Zr(m, pairing);
    element_init_Zr(h1, pairing);
    element_init_Zr(h2, pairing);
    element_init_Zr(C4, pairing);
    element_init_Zr(C4_Left, pairing);

    element_init_G1(tmp, pairing);
    element_init_G1(C1, pairing);
    element_init_G1(C2, pairing);
    element_init_G1(pk1, pairing);
    element_init_G1(pk2, pairing);

    element_init_GT(C3_Pair, pairing);
    element_init_GT(C4_Pair, pairing);

    element_random(r1);
    element_random(r2);
    element_to_bytes(strR2, r2);

    element_from_bytes(pk1, (unsigned char *)pk.pk1);
    element_from_bytes(pk2, (unsigned char *)pk.pk2);

    H1(ID, ID_SPACE, hashID, SHA256_DIGEST_LENGTH);
    H1(M, lenG1, hashM, SHA256_DIGEST_LENGTH);
    H2(pk.pk1, lenG1, hash1, SHA256_DIGEST_LENGTH);
    H2(pk.pk2, lenG1, hash2, SHA256_DIGEST_LENGTH);

    element_from_hash(HID, hashID, SHA256_DIGEST_LENGTH);
    element_from_hash(m, hashM, SHA256_DIGEST_LENGTH);
    element_from_hash(h1, hash1, SHA256_DIGEST_LENGTH);
    element_from_hash(h2, hash2, SHA256_DIGEST_LENGTH);

    element_mul_zn(tmp, P, HID);
    element_add(C1, tmp, P1);
    element_mul_zn(C1, C1, h1);
    element_add(C1, C1, pk1);
    element_mul_zn(C1, C1, r1);

    element_add(C2, tmp, P2);
    element_mul_zn(C2, C2, h2);
    element_add(C2, C2, pk2);
    element_mul_zn(C2, C2, r2);

    element_pow_zn(C4_Pair, g, r2); // e(P, P)^r2
    element_to_bytes(strC4_Pair, C4_Pair);

    element_mul(C4_Left, m, r2); // m * r2
    element_to_bytes(strC4_Left, C4_Left);

    H4(strC4_Pair, lenGT, strC4_Right, SHA256_DIGEST_LENGTH);
    element_from_hash(C4, strC4_Right, SHA256_DIGEST_LENGTH);
    element_mul(C4, C4, C4_Left);

    element_pow_zn(C3_Pair, g, r1);
    element_to_bytes(strC3_Pair, C3_Pair);

    memcpy(strC3_Right, strC3_Pair, lenGT);
    memcpy(strC3_Right + lenGT, strC4_Left, lenZr);
    H3(strC3_Right, lenGT + lenZr, strC3_Hash, lenG1 + lenZr);

    memcpy(strC3_Left, M, lenG1);
    memcpy(strC3_Left + lenG1, strR2, lenZr);

    for (int i = 0; i < lenG1 + lenZr; i++)
    {
        C->C3[i] = strC3_Left[i] ^ strC3_Hash[i];
    }

    element_to_bytes(C->C1, C1);
    element_to_bytes(C->C2, C2);
    element_to_bytes(C->C4, C4);

    element_clear(r1);
    element_clear(r2);
    element_clear(C1);
    element_clear(C2);
    element_clear(C4);
    element_clear(C3_Pair);
    element_clear(C4_Pair);
    element_clear(C4_Left);
    element_clear(tmp);
    element_clear(h1);
    element_clear(h2);
    element_clear(pk1);
    element_clear(pk2);
    element_clear(HID);
    element_clear(m);
    delete[] hashID;
    delete[] hashM;
    delete[] hash1;
    delete[] hash2;
    delete[] strC3_Left;
    delete[] strC3_Right;
    delete[] strC3_Hash;
    delete[] strC3_Pair;
    delete[] strC4_Pair;
    delete[] strC4_Left;
    delete[] strC4_Right;
    delete[] strR2;

    return C;
}
unsigned char *MCL_PKC_ET::Decrypt(const KEY sk, const CIPHER C, const unsigned char *ID, const PK pk)
{
    element_t C1, C2, C4;
    element_t sk1, sk2;
    element_t pk2;
    element_t h1, h2;
    element_t m, HID, r2;
    element_t C3_Pair;
    element_t C4_Pair, C4_Right;
    element_t verifyC2, verifyK;
    element_t k;

    unsigned char *M = new unsigned char[lenG1];
    unsigned char *hashM = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *hashID = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *hash1 = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *hash2 = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *strR2 = new unsigned char[lenZr];
    unsigned char *strK = new unsigned char[lenZr];
    unsigned char *strC3_Pair = new unsigned char[lenGT];
    unsigned char *strC4_Pair = new unsigned char[lenGT];
    unsigned char *strC3_Left = new unsigned char[lenG1 + lenZr];
    unsigned char *strC3_Right = new unsigned char[lenGT + lenZr];
    unsigned char *strC3_Hash = new unsigned char[lenG1 + lenZr];
    unsigned char *strC4_Right = new unsigned char[lenZr];

    memset(M, 0x00, lenG1);
    memset(strC3_Pair, 0x00, lenGT);
    memset(strC4_Pair, 0x00, lenGT);
    memset(strC3_Left, 0x00, lenG1 + lenZr);
    memset(strC3_Right, 0x00, lenGT + lenZr);
    memset(strR2, 0x00, lenZr);
    memset(strK, 0x00, lenZr);

    element_init_Zr(m, pairing);
    element_init_Zr(HID, pairing);
    element_init_Zr(h1, pairing);
    element_init_Zr(h2, pairing);
    element_init_Zr(r2, pairing);
    element_init_Zr(k, pairing);
    element_init_Zr(verifyK, pairing);
    element_init_Zr(C4, pairing);
    element_init_Zr(C4_Right, pairing);

    element_init_G1(C1, pairing);
    element_init_G1(C2, pairing);
    element_init_G1(sk1, pairing);
    element_init_G1(sk2, pairing);
    element_init_G1(pk2, pairing);
    element_init_G1(verifyC2, pairing);

    element_init_GT(C3_Pair, pairing);
    element_init_GT(C4_Pair, pairing);

    element_from_bytes(C1, (unsigned char *)C.C1);
    element_from_bytes(C2, (unsigned char *)C.C2);
    element_from_bytes(C4, (unsigned char *)C.C4);

    element_from_bytes(sk1, (unsigned char *)sk.key1);
    element_from_bytes(sk2, (unsigned char *)sk.key2);
    element_from_bytes(pk2, (unsigned char *)pk.pk2);

    H2(pk.pk1, lenG1, hash1, SHA256_DIGEST_LENGTH);
    H2(pk.pk2, lenG1, hash2, SHA256_DIGEST_LENGTH);

    element_from_hash(h1, hash1, SHA256_DIGEST_LENGTH);
    element_from_hash(h2, hash2, SHA256_DIGEST_LENGTH);

    element_pairing(C3_Pair, C1, sk1);
    element_pairing(C4_Pair, C2, sk2);

    element_to_bytes(strC4_Pair, C4_Pair);
    H4(strC4_Pair, lenGT, strC4_Right, SHA256_DIGEST_LENGTH);
    element_from_hash(C4_Right, strC4_Right, SHA256_DIGEST_LENGTH);
    element_div(k, C4, C4_Right);
    element_to_bytes(strK, k);

    element_to_bytes(strC3_Pair, C3_Pair);
    memcpy(strC3_Right, strC3_Pair, lenGT);
    memcpy(strC3_Right + lenGT, strK, lenZr);

    H3(strC3_Right, lenGT + lenZr, strC3_Hash, lenG1 + lenZr);

    for (int i = 0; i < lenG1 + lenZr; i++)
    {
        strC3_Left[i] = C.C3[i] ^ strC3_Hash[i];
    }

    memcpy(M, strC3_Left, lenG1);
    memcpy(strR2, strC3_Left + sizeof(unsigned char) * lenG1, lenZr);

    H1(M, lenG1, hashM, SHA256_DIGEST_LENGTH);
    H1(ID, ID_SPACE, hashID, SHA256_DIGEST_LENGTH);

    element_from_hash(m, hashM, SHA256_DIGEST_LENGTH);
    element_from_hash(HID, hashID, SHA256_DIGEST_LENGTH);
    element_from_bytes(r2, strR2);

    element_mul_zn(verifyC2, P, HID);
    element_add(verifyC2, verifyC2, P2);
    element_mul_zn(verifyC2, verifyC2, h2);
    element_add(verifyC2, verifyC2, pk2);
    element_mul_zn(verifyC2, verifyC2, r2);

    element_mul(verifyK, m, r2);

    if (element_cmp(C2, verifyC2) || element_cmp(k, verifyK))
    {
        printf("Decryption phase : verification fails\n");
        abort();
    }

    element_clear(C1);
    element_clear(C2);
    element_clear(C4);
    element_clear(sk1);
    element_clear(sk2);
    element_clear(pk2);
    element_clear(h1);
    element_clear(h2);
    element_clear(m);
    element_clear(HID);
    element_clear(r2);
    element_clear(C3_Pair);
    element_clear(C4_Pair);
    element_clear(C4_Right);
    element_clear(verifyC2);
    element_clear(k);
    element_clear(verifyK);
    delete[] hashM;
    delete[] hashID;
    delete[] hash1;
    delete[] hash2;
    delete[] strR2;
    delete[] strC3_Pair;
    delete[] strC4_Pair;
    delete[] strC3_Left;
    delete[] strC3_Right;
    delete[] strC3_Hash;
    delete[] strC4_Right;
    delete[] strK;

    return M;
}

pairing_t *MCL_PKC_ET::getPairing()
{
    return &this->pairing;
}

int MCL_PKC_ET::getLenG1()
{
    return this->lenG1;
}
int MCL_PKC_ET::getLenGT()
{
    return this->lenGT;
}
int MCL_PKC_ET::getLenZr()
{
    return this->lenZr;
}

void MCL_PKC_ET::H1(const unsigned char *src, const int slen, unsigned char *dest, int dlen)
{
    memset(dest, 0x00, dlen);

    SHA256(src, slen, dest);
}
void MCL_PKC_ET::H2(const unsigned char *src, const int slen, unsigned char *dest, int dlen)
{
    memset(dest, 0x00, dlen);

    SHA256(src, slen, dest);
}
void MCL_PKC_ET::H3(const unsigned char *src, const int slen, unsigned char *dest, int dlen)
{
    memset(dest, 0x00, dlen);
    for (int i = 0; i <= dlen / SHA512_DIGEST_LENGTH; i++)
    {
        unsigned char *pair_buf = new unsigned char[slen + 2];
        unsigned char *hash_buf = new unsigned char[SHA512_DIGEST_LENGTH];

        memset(pair_buf, 0x00, slen + 2);
        memset(hash_buf, 0x00, SHA512_DIGEST_LENGTH);

        memcpy(pair_buf, src, slen);

        strcat((char *)pair_buf, to_string(i).c_str());
        SHA512(pair_buf, slen + 2, hash_buf);

        if (i < dlen / SHA512_DIGEST_LENGTH)
            memcpy(dest + i * SHA512_DIGEST_LENGTH, hash_buf, SHA512_DIGEST_LENGTH);
        else
            memcpy(dest + i * SHA512_DIGEST_LENGTH, hash_buf, dlen - SHA512_DIGEST_LENGTH * i);

        delete[] pair_buf;
        delete[] hash_buf;
    }
}
void MCL_PKC_ET::H4(const unsigned char *src, const int slen, unsigned char *dest, int dlen)
{
    memset(dest, 0x00, dlen);
    SHA256(src, slen, dest);
}

unsigned char *MCL_PKC_ET::aut(const KEY sk)
{
    unsigned char *td = new unsigned char[lenG1];
    memcpy(td, sk.key2, lenG1);

    return td;
}
bool MCL_PKC_ET::test(const CIPHER Ci, const unsigned char *_tdi, const CIPHER Cj, const unsigned char *_tdj)
{
    element_t Ci2, Cj2;
    element_t Ci4, Cj4;
    element_t cmp1, cmp2;
    element_t tmp1, tmp2;
    element_t tdi, tdj;
    element_t Qi, Qj;
    element_t Ri, Rj;

    unsigned char *strQi = new unsigned char[lenGT];
    unsigned char *strQj = new unsigned char[lenGT];
    unsigned char *hashQi = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *hashQj = new unsigned char[SHA256_DIGEST_LENGTH];

    element_init_Zr(Ri, pairing);
    element_init_Zr(Rj, pairing);
    element_init_Zr(Ci4, pairing);
    element_init_Zr(Cj4, pairing);

    element_init_Zr(tmp1, pairing);
    element_init_Zr(tmp2, pairing);

    element_init_G1(tdi, pairing);
    element_init_G1(tdj, pairing);
    element_init_G1(Ci2, pairing);
    element_init_G1(Cj2, pairing);

    element_init_GT(Qi, pairing);
    element_init_GT(Qj, pairing);
    element_init_GT(cmp1, pairing);
    element_init_GT(cmp2, pairing);

    element_from_bytes(Ci2, (unsigned char *)Ci.C2);
    element_from_bytes(Cj2, (unsigned char *)Cj.C2);
    element_from_bytes(Ci4, (unsigned char *)Ci.C4);
    element_from_bytes(Cj4, (unsigned char *)Cj.C4);
    element_from_bytes(tdi, (unsigned char *)_tdi);
    element_from_bytes(tdj, (unsigned char *)_tdj);

    element_pairing(Qi, tdi, Ci2);
    element_pairing(Qj, tdj, Cj2);

    element_to_bytes(strQi, Qi);
    element_to_bytes(strQj, Qj);

    H4(strQi, lenGT, hashQi, SHA256_DIGEST_LENGTH);
    H4(strQj, lenGT, hashQj, SHA256_DIGEST_LENGTH);

    element_from_hash(Ri, hashQi, SHA256_DIGEST_LENGTH);
    element_from_hash(Rj, hashQj, SHA256_DIGEST_LENGTH);

    element_div(Ri, Ci4, Ri);
    element_div(Rj, Cj4, Rj);

    element_mul_zn(cmp1, Qi, Rj);
    element_mul_zn(cmp2, Qj, Ri);


    if (!element_cmp(cmp1, cmp2))
        return true;
    else
        return false;
}