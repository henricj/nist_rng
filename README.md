nist_rng
========

NIST SP 800-90 CTR\_DRBG

From http://henric.info/random/#nistrng

This code implements a random number generator based on section 10.2 DRBG Mechanisms Based on Block Ciphers in NIST SP 800-90. More specifically, it implements CTR_DRBG with a derivation function using AES-256 (see FIPS 197) as the block encryption function.

Security strength, prediction resistance, and the like apply to a higher level interface than is currently implemented (the algorithm as implemented can be used to support prediction resistance and a security strength of up to 256).

It gives the same output on i386/OpenBSD, amd64/FreeBSD and Windows, but without test vectors one shouldn't say a whole lot more about that output (DIEHARD seems happy, but that could be true even if things were severely screwed up).

There are known-answer tests included in the kat directory for the Rijndael code, but not for CTR_DRBG (I'm still looking for test vectors). Both the VIA padlock implementation and the default software implementation match the corresponding NIST test vectors.

A new version of c7random is included that adds a full entropy NIST CTR\_DRBG random number generator (command line option “-N”). The result should be something along the lines of NIST SP 800-90 Appendix D. It's intended to be consistent with an “RBG” as described in D.1.b and D.2.1—minus runtime tests and such decidedly non-trivial details. For every 16 bytes of output, it consumes at least 18 bytes from the CPU's entropy source. Should the CPU stop generating entropy output the program will stop outputting data, but the entropy output is not validated in any way. Have nist\_config.h include nist\_aes\_padlock.h instead of nist\_aes\_rijndael.h to use the CPU's AES hardware (c7random always uses the C3/7's hardware entropy). “c7random -N” does not require hardware SHA support, so it works on earlier VIA CPUs that only have the AES and RNG options.

There are number of things to keep in mind:
•The API should be based on the “envelope” described in chapter 9 and section F.3.2. So far, only the section 10.2 algorithm is implemented.
•The RBG code lacks both test vectors and a way to validate them.
•Some basic runtime self-tests need to be implemented (and enforced by the various API functions).
•The code should be reviewed to make sure it is consistent with SP 800-90 (there are comments throughout the code referencing the relevant parts of SP 800-90).
•The Makefiles will likely need some tweaks for anything other than OpenBSD (there are project files for Microsoft Visual Studio 2005 for building both 32-bit and 64-bit executables).
