/**MCL-PKC-ET.h**/
#ifndef __MODIFIED_CL_PKC_ET_H__
#define __MODIFIED_CL_PKC_ET_H__

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define ID_SPACE 32
#define Zp_SPACE 32 // n2

    typedef struct
    {
        unsigned char *C1;
        unsigned char *C2;
        unsigned char *C3;
        unsigned char *C4;
    } CIPHER;

    typedef struct
    {
        unsigned char *pk1;
        unsigned char *pk2;
        unsigned char *pk3;
    } PK;

    typedef struct
    {
        unsigned char *key1;
        unsigned char *key2;
    } KEY;

    class MCL_PKC_ET
    {

    private:
        pairing_t pairing;
        element_t s1, s2;       // master secret key
        element_t g, P, P1, P2; // public parameters
        bool flag;
        int lenG1;
        int lenGT;
        int lenZr;

    public:
        MCL_PKC_ET(/*int lambda = 80*/);
        MCL_PKC_ET(int argc, char **argv);
        ~MCL_PKC_ET();

        void init();
        void clear();

        CIPHER *Encrypt(const unsigned char *ID, const PK pk, const unsigned char *M);
        unsigned char *Decrypt(const KEY sk, const CIPHER C, const unsigned char *ID, const PK pk);

        unsigned char *Extract_Private_Value();
        KEY *Extract_Partial_Private_Key(const unsigned char *ID);
        KEY *Extract_Private_Key(const KEY dk, const unsigned char *x, const PK pk);
        PK *Extract_Public_Key(const unsigned char *x, unsigned char *ID);
        void Verify_Public_Key(const PK pk);

        unsigned char *aut(const KEY sk);
        bool test(const CIPHER Ci, const unsigned char *_tdi, const CIPHER Cj, const unsigned char *_tdj);

        pairing_t *getPairing();
        int getLenG1();
        int getLenGT();
        int getLenZr();

        void H1(const unsigned char *src, const int slen, unsigned char *dest, int dlen);
        void H2(const unsigned char *src, const int slen, unsigned char *dest, int dlen);
        void H3(const unsigned char *src, const int slen, unsigned char *dest, int dlen);
        void H4(const unsigned char *src, const int slen, unsigned char *dest, int dlen);
    };

#ifdef __cplusplus
}
#endif

#endif