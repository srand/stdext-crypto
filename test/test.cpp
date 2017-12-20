#include <gtest/gtest.h>
#include <stdext/crypto.h>

template <class HashFunction>
bool equals(const char *input, const char *digesthex) {
  typename HashFunction::digest_type expected(digesthex);

  HashFunction s;
  typename HashFunction::digest_type digest;
  s.update(input, strlen(input));
  digest = s.finalize();
  std::cout << digest.str() << std::endl;
  return expected == digest;
}

TEST(Sha1Sum, UpdateAndFinalize) {
  struct {
    const char *input;
    const char *digest;
  } testVectors[] = {
      {"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
      {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
      {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmno"
       "pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
       "a49b2446a02c645bf419f995b67091253a04a259"}};

  for (auto &test : testVectors) {
    EXPECT_TRUE(equals<stdext::sha1sum>(test.input, test.digest));
  }
}

TEST(CSha256Hash, UpdateAndFinalize) {
  struct {
    const char *input;
    const char *digest;
  } testVectors[] = {
      {"abc",
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmno"
       "pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
       "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"}};

  for (auto &test : testVectors) {
    EXPECT_TRUE(equals<stdext::sha256sum>(test.input, test.digest));
  }
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}