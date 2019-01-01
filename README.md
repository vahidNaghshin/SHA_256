# SHA_256

  Secure Hash Algorithm (SHA) is a cryptographic hash function which takes a message of variable length and produces a fixed-size hash value, a.k.a. message digest. SHA came in different versions with different configuration. SHA-1 produces 160-bit output while SHA-2 family consists of six hash functions with digests (hash values) that are 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.
Here, the cpp implementation of the SHA-256 is presented. The code takes message to be hashed by setting the “msg” variable in the code and running it. 

Note that, the implementation assumes that the message to be hashed is less than 512 bits length (64 characters). However, extending the implementation to the message of general size is trivial.
 
