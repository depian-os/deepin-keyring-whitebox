#include <gtest/gtest.h>

#include "common.h"
#include "dkkey.h"
#include "global_test_env.h"

// TestDkKey依赖外部运行环境，gerrit无法通过
// 如需运行，使用--gtest_also_run_disabled_tests参数
class DISABLED_TestDkKey : public testing::Test
{
public:
    void SetUp() override { ASSERT_NE(TestEnv::testWorkDir, ""); }

    void TearDown() override { }
};

TEST_F(DISABLED_TestDkKey, GenerateRandomKey)
{
    char *key = nullptr;
    do {
        EXPECT_TRUE(dk_key_generate_random_key(&key));
        if (HasFailure()) {
            break;
        }
        EXPECT_EQ(strlen(key), MASTER_KEY_LEN);
        if (HasFailure()) {
            break;
        }
    } while (false);

    if (key != nullptr) {
        free(key);
    }
}

TEST_F(DISABLED_TestDkKey, GenerateIodinesalt)
{
    char *iodine = nullptr;
    char *iodineEncHex = nullptr;
    do {
        char zkey[VALID_LENGTH] = { 0 };
        EXPECT_TRUE(dk_key_generate_iodinesalt(zkey, &iodine, &iodineEncHex));
        if (HasFailure()) {
            break;
        }
        EXPECT_EQ(strlen(iodine), MASTER_KEY_LEN);
        EXPECT_EQ(strlen(iodineEncHex), MASTER_KEY_LEN * 2);
        if (HasFailure()) {
            break;
        }
    } while (false);
    if (iodine != nullptr) {
        free(iodine);
    }
    if (iodineEncHex != nullptr) {
        free(iodineEncHex);
    }
}

TEST_F(DISABLED_TestDkKey, InitSalt)
{
    char *salt1 = nullptr;
    char *salt2 = nullptr;
    do {
        EXPECT_TRUE(dk_key_init_salt(TestEnv::testWorkDir.c_str(), &salt1));
        if (HasFailure()) {
            break;
        }
        EXPECT_TRUE(dk_key_get_salt(TestEnv::testWorkDir.c_str(), &salt2));
        if (HasFailure()) {
            break;
        }
        EXPECT_STREQ(salt1, salt2);
        if (HasFailure()) {
            break;
        }
    } while (false);

    if (salt1 != nullptr) {
        free(salt1);
    }
    if (salt2 != nullptr) {
        free(salt2);
    }
}

TEST_F(DISABLED_TestDkKey, KeyInit)
{
    char *key = nullptr;
    do {
        EXPECT_TRUE(dk_key_init(TestEnv::testWorkDir.c_str()));
        if (HasFailure()) {
            break;
        }
        EXPECT_TRUE(dk_key_get_masterkey(TestEnv::testWorkDir.c_str(), &key));
        if (HasFailure()) {
            break;
        }
    } while (false);
    if (key != nullptr) {
        free(key);
    }
}