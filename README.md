CryptoJPM
=========

public fork of Crypto++ v5.6.2 to add algorithms

algorithms include:
- Skein
- Threefish
- Fortuna(unfinished)
- BLAKE2s/b/sp/bp (unfinished/bugged?)
- scrypt (unfinished/bugged?)

planned algorithms:
- post-quantum public key cryptography (mceliece?)
- PHC winner(s)

production use is NOT recommended

You can use some parts of this fork for production use.
If you are on a little-endian machine (x86, x64, ARM) you can use everything but scrypt, BLAKE2s/sp and if on X86 you can't use BLAKE2b/bp.
Usage of Fortuna is strongly not recommended, as this is unfinished yet.
Everything else SHOULD be fine, but is not guaranteed to be so.

SSE code of BLAKE2s, BLAKE2sp, scrypt and x86-BLAKE2b and X86-BLAKE2bp is broken and produces wrong results (as far as my tests go, test code is included)

What needs to be done:
- If you wish you can review every piece of code
- Fortuna random event collecting code is currently wip
- one can test/correct the above mentioned (broken) SSE codes
- one can contribute planned algorithms(orient at Crypto++/CryptoJPM's style of formatting and class structures), note that the file header should be set and the code will be placed in the public domain