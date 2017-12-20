from build.model import *
from externals.googletest import googletest

stdext_crypto = cxx_library(
    name = "stdext-crypto",
    incpaths = [("include", {"publish": True})],
    sources = ["src/crypto.cpp"],
    features = ["language-c++11"],
    libraries = [("crypto", {"publish": True, "filter": "linux"})]
)

stdext_crypto_test = cxx_executable(
    name = "stdext-crypto-test",
    sources = ["test/test.cpp"],
    dependencies = [googletest, stdext_crypto],
    features = ["language-c++11"]
)

