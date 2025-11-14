#include <gtest/gtest.h>

#include "dkfile.h"
#include "global_test_env.h"

#include <pwd.h>

class TestDkFile : public testing::Test
{
public:
    void SetUp() override { ASSERT_NE(TestEnv::testWorkDir, ""); }

    void TearDown() override { }
};

TEST_F(TestDkFile, GetWorkDir)
{
    char *workDir = nullptr;
    char *workDir2 = nullptr;
    do {
        std::string dir = "/home/test1/.local/share/" + std::string(dk_file_get_workdir_name());
        EXPECT_TRUE(dk_file_get_workdir("/home/test1/", &workDir));
        if (HasFailure()) {
            break;
        }
        EXPECT_EQ(dir, std::string(workDir));
        if (HasFailure()) {
            break;
        }

        EXPECT_TRUE(dk_file_get_workdir("/home/test1", &workDir2));
        if (HasFailure()) {
            break;
        }
        EXPECT_EQ(dir, std::string(workDir2));
        if (HasFailure()) {
            break;
        }
    } while (false);

    if (workDir != nullptr) {
        free(workDir);
    }
    if (workDir2 != nullptr) {
        free(workDir2);
    }
}

TEST_F(TestDkFile, FullTest)
{
    struct passwd *pwd = getpwuid(getuid());
    ASSERT_TRUE(pwd != nullptr);
    ASSERT_TRUE(dk_file_md5_init(TestEnv::testWorkDir.c_str(), pwd->pw_uid, pwd->pw_gid));
    int isExist = 0;
    ASSERT_TRUE(dk_file_md5_exist(TestEnv::testWorkDir.c_str(), &isExist));
    ASSERT_EQ(isExist, 1);
    std::string cmdGenerateTestFile = "echo 123 > " + TestEnv::testWorkDir + "/" + "test.keyring";
    int cmdRet = system(cmdGenerateTestFile.c_str());
    ASSERT_GE(cmdRet, 0);
    ASSERT_TRUE(dk_file_md5_gen(TestEnv::testWorkDir.c_str(), TestEnv::testWorkDir.c_str(), "test.keyring", pwd->pw_uid, pwd->pw_gid));
}