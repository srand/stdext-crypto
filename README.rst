=============
stdext-crypto
=============
Cryptographic utilities in C++

Usage
-----

Example:
::
   stdext::sha1sum sha1;
   sha1.update("Hello world");
   stdext::sha1sum::digest_type sha1digest = sha1.finalize();
   for (auto byte : sha1digest) {
       std::cout << hex << byte;
   }
   std::cout << std::endl << sha1digest.size() << " bytes" << std::endl;   

   stdext::sha256sum sha256;
   sha256.update("Hello");
   std::cout << sha256.finalize().str() << std::endl;

Build
-----

Use Pam, http://github.com/srand/pam
::
   from externals.stdext import stdext_crypto

   cxx_executable(
      name = "hello",
      sources = ["hello.cpp"],
      dependencies = [stdext_crypto]
   )
