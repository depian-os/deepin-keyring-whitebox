#include "global_test_env.h"

#include "dklog.h"

std::string TestEnv::testWorkDir = "";

void TestEnv::SetUp()
{
    dk_log_init(-1, "");
    const char *dir = "./testdata_workdir_temp";
    if (0 == access(dir, F_OK)) {
        FAIL() << "test workdir(testdata_workdir_temp) is existed?";
    }
    int mkret = mkdir(dir, 0700);
    ASSERT_EQ(mkret, 0);
    TestEnv::testWorkDir = dir;
}

void TestEnv::TearDown()
{
    if (!TestEnv::testWorkDir.empty()) {
        std::string cmd = "rm -r " + TestEnv::testWorkDir;
        system(cmd.c_str());
        TestEnv::testWorkDir = "";
    }
}
