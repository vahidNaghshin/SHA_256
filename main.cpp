#include <iostream>
#include <bitset>
#include <cstring>
#include <fstream>
#include <sstream>
#include <cmath>




uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*Initialize hash values:
 Obtained by taking the fractional part of the square roots of first eight prime numbers
 */
uint32_t h0 = 0x6a09e667;
uint32_t h1 = 0xbb67ae85;
uint32_t h2 = 0x3c6ef372;
uint32_t h3 = 0xa54ff53a;
uint32_t h4 = 0x510e527f;
uint32_t h5 = 0x9b05688c;
uint32_t h6 = 0x1f83d9ab;
uint32_t h7 = 0x5be0cd19;

void Split64BitTobyte (uint64_t& len, unsigned char& pad, int& j)
{
    pad = len >> (j*8);
}

uint32_t Ch(uint32_t& x, uint32_t& y, uint32_t& z)
{
    return (((x) & (y)) ^ (~(x) & (z)));
}

uint32_t Maj(uint32_t& x, uint32_t& y, uint32_t& z)
{
    return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
    
}

uint32_t rotateLeft(uint32_t& a, int l)
{
    return (a << l) | ((a) >> (32-l));
}

uint32_t rotateright(uint32_t& a, int r)
{
    return (a >> r) | (a << (32-r));
}


uint32_t SIG0(uint32_t& a)
{
    uint32_t R1, R2, R3;
    R1 = rotateright(a,2);
    R2 = rotateright(a,13);
    R3 = rotateright(a,22);
    return R1 ^ R2 ^ R3;
}

uint32_t SIG1(uint32_t& a)
{
    uint32_t R1, R2, R3;
    R1 = rotateright(a,6);
    R2 = rotateright(a,11);
    R3 = rotateright(a,25);
    return R1 ^ R2 ^ R3;
}


uint32_t sigma0(uint32_t& a)
{
    uint32_t R1, R2;
    R1 = rotateright(a,7);
    R2 = rotateright(a,18);
    return R1 ^ R2 ^ (a >> 3);
}

uint32_t sigma1(uint32_t& a)
{
    uint32_t R1, R2;
    R1 = rotateright(a,17);
    R2 = rotateright(a,19);
    return R1 ^ R2 ^ (a >> 10);
}




void WordExpansion(unsigned char paddedMessage[], uint32_t W[])
{
    for(int k=0; k < 16; k++)
    {
        uint32_t _aux;
        for(int z=0; z<4; z++)
        {
            _aux = paddedMessage[(4 * k ) + z];
            _aux = _aux << (8 * ( 3 - z ));
            
            W[k] |= _aux;
        }
        
    }
    
    for(int j=16; j < 64; j++)
    {
        W[j] = sigma1(W[j-2])+W[j-7]+sigma0(W[j-15])+W[j-16];
    }
}


void SHA_256(unsigned char msg[], unsigned long int& originalLen, unsigned long int& lenOfZeroPaddedMessage, unsigned long int& lenOflengthOfMsg, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t& e,
             uint32_t& f,
             uint32_t& g,
             uint32_t& h, uint32_t state[])
{
    const int modulo_448_512 = 448;
    
    if (originalLen % 512 <= 448)
    {
        lenOfZeroPaddedMessage = modulo_448_512 - ((originalLen * 8) + 1);
    }
   
    lenOfZeroPaddedMessage += 1 ;
    lenOflengthOfMsg = 512 - lenOfZeroPaddedMessage - (originalLen * 8);

    
    unsigned char* paddedMessage = new unsigned char [64];
    uint64_t lastPad = originalLen * 8;
    int idx=7;
    for (int i=0; i < 64; i++)
    {
        if((i>=originalLen + 1) && i < 56) paddedMessage[i]=0;
        else if (i>= 56)
        {
            Split64BitTobyte (lastPad, paddedMessage[i], idx);
            idx--;
        }
        else if(i == originalLen) paddedMessage[i]=pow(2, 7);
        else paddedMessage[i]=msg[i];
    }
    uint32_t W[64]={0};
    WordExpansion(paddedMessage, W);

    for (int i=0; i<64; i++)
    {
        uint32_t T1, T2;
        
        T1 = h + SIG1(e) + Ch(e,f,g) + K[i] + W[i];
        T2 = SIG0(a) + Maj(a,b,c);
        h=g;
        g=f;
        f=e;
        e=d+T1;
        d=c;
        c=b;
        b=a;
        a=T1+T2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

int main()
{
    unsigned char msg [] = "The message to be hashed!";
    unsigned long int originalLen= std::strlen((const char*) msg);
    unsigned long int lenOfZeroPaddedMessage = 0;
    unsigned long int lenOflengthOfMsg = 0;
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    uint32_t state[8]={h0, h1, h2, h3, h4, h5, h6, h7};

    SHA_256(msg, originalLen, lenOfZeroPaddedMessage, lenOflengthOfMsg, a, b, c, d, e, f, g, h, state);
    
    std::cout << "messgae digest: " << std::hex << state[0] << state[1] << state[2]<< state[3]<< state[4] << state[5] << state[6] << state[7] << std::endl;
    return 0;
}
