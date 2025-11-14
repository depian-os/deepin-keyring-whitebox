#include <gtest/gtest.h>

#include "common.h"
#include "global_test_env.h"

class TestCommon : public testing::Test
{
public:
    void SetUp() override { ASSERT_NE(TestEnv::testWorkDir, ""); }

    void TearDown() override { }
};

TEST_F(TestCommon, FileTest)
{
    char *readData = nullptr;

    do {
        std::string srcFilePath = TestEnv::testWorkDir + "/testcommon_filetest.src";
        std::string dstFilePath = TestEnv::testWorkDir + "/testcommon_filetest.dst";
        std::string cmdGenerateTestFile = "echo 123abc > " + srcFilePath;
        int cmdRet = system(cmdGenerateTestFile.c_str());
        EXPECT_GE(cmdRet, 0);
        if (HasFailure()) {
            break;
        }
        int len = copy_by_fileio(srcFilePath.c_str(), dstFilePath.c_str());
        EXPECT_GE(len, 6);
        if (HasFailure()) {
            break;
        }
        char *readData = read_file_data(dstFilePath.c_str());
        EXPECT_TRUE(strncmp(readData, "123abc", strlen("123abc")) == 0);
        if (HasFailure()) {
            break;
        }
    } while (false);

    if (readData != nullptr) {
        free(readData);
    }
}

TEST_F(TestCommon, ArgsTest)
{
    const char *argv[] = { "deepin-keyring-whitebox", "--opt=abc", "--wait", "--novalue=", "--opt-2", "-single", "test" };
    char *arg1 = nullptr;
    char *arg2 = nullptr;
    char *arg3 = nullptr;
    char *arg4 = nullptr;
    char *arg5 = nullptr;
    char *arg6 = nullptr;

    do {
        argHandler argh;
        EXPECT_TRUE(arg_parse(7, (char **)argv, &argh));
        if (HasFailure()) {
            break;
        }

        EXPECT_TRUE(arg_has_key(&argh, "--opt"));
        if (HasFailure()) {
            break;
        }
        EXPECT_TRUE(arg_has_key(&argh, "--wait"));
        if (HasFailure()) {
            break;
        }
        EXPECT_TRUE(arg_has_key(&argh, "--novalue"));
        if (HasFailure()) {
            break;
        }
        EXPECT_TRUE(arg_has_key(&argh, "--opt-2"));
        if (HasFailure()) {
            break;
        }
        EXPECT_FALSE(arg_has_key(&argh, "-single"));
        if (HasFailure()) {
            break;
        }
        EXPECT_FALSE(arg_has_key(&argh, "test"));
        if (HasFailure()) {
            break;
        }

        EXPECT_TRUE(arg_get_value(&argh, "--opt", &arg1));
        EXPECT_STREQ(arg1, "abc");
        if (HasFailure()) {
            break;
        }
        EXPECT_TRUE(arg_get_value(&argh, "--wait", &arg2));
        EXPECT_STREQ(arg2, "");
        if (HasFailure()) {
            break;
        }
        EXPECT_TRUE(arg_get_value(&argh, "--novalue", &arg3));
        EXPECT_STREQ(arg3, "");
        if (HasFailure()) {
            break;
        }
        EXPECT_TRUE(arg_get_value(&argh, "--opt-2", &arg4));
        EXPECT_STREQ(arg4, "");
        if (HasFailure()) {
            break;
        }
        EXPECT_FALSE(arg_get_value(&argh, "-single", &arg6));
        if (HasFailure()) {
            break;
        }
        EXPECT_FALSE(arg_get_value(&argh, "test", &arg6));
        if (HasFailure()) {
            break;
        }

        EXPECT_TRUE(arg_clean(&argh));
        if (HasFailure()) {
            break;
        }
        EXPECT_FALSE(arg_has_key(&argh, "--opt"));
        if (HasFailure()) {
            break;
        }
    } while (false);

    if (arg1 != nullptr) {
        free(arg1);
    }
    if (arg2 != nullptr) {
        free(arg2);
    }
    if (arg3 != nullptr) {
        free(arg3);
    }
    if (arg4 != nullptr) {
        free(arg4);
    }
    if (arg5 != nullptr) {
        free(arg5);
    }
    if (arg6 != nullptr) {
        free(arg6);
    }
}

TEST_F(TestCommon, HexTest)
{
    char *hexData = nullptr;
    const char *randomData[10] = {
        "sdfDFG124sdf23Fe", "kdn3hd7F61hf8shD", "2jfnxhd7NHjhf7fh", "mxhd762gsduxbffF", "djxnd837Hf7dg32F",
        "1111111111111111", "ffffffffffffffff", "PPPPPPPPPPPPPPPP", "1312312312312312", "dsfsdfsdfsdfsdff",
    };
    for (const auto *orgData : randomData) {
        if (hexData != nullptr) {
            free(hexData);
            hexData = nullptr;
        }
        int hexDataLen = hex_encode_to_string((unsigned char *)orgData, strlen(orgData), &hexData);
        EXPECT_EQ(hexDataLen, 32);
        EXPECT_TRUE(hexData != nullptr);
        if (HasFailure()) {
            break;
        }
        char data[17] = { 0 };
        unsigned int dataLen = 0;
        hex_decode_string(hexData, (unsigned char *)data, &dataLen);
        EXPECT_EQ(dataLen, 16);
        EXPECT_STREQ(orgData, data);
        if (HasFailure()) {
            break;
        }
    }

    if (hexData != nullptr) {
        free(hexData);
    }
}
