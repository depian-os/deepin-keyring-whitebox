#include <gtest/gtest.h>

#include "dkconfig.h"
#include "global_test_env.h"

class TestDkConfig : public testing::Test
{
public:
    void SetUp() override { ASSERT_NE(TestEnv::testWorkDir, ""); }

    void TearDown() override { }
};

TEST_F(TestDkConfig, FullTest)
{
    if (!dk_config_readfile(TestEnv::testWorkDir.c_str())) {
        ASSERT_TRUE(dk_config_writefile(TestEnv::testWorkDir.c_str()));
    }
    ASSERT_TRUE(dk_config_set_enable(TestEnv::testWorkDir.c_str(), false));
    ASSERT_TRUE(dk_config_set_is_wb_data(TestEnv::testWorkDir.c_str(), false));

    ASSERT_FALSE(dk_config_enable(TestEnv::testWorkDir.c_str()));
    ASSERT_FALSE(dk_config_is_wb_data(TestEnv::testWorkDir.c_str()));

    ASSERT_TRUE(dk_config_set_enable(TestEnv::testWorkDir.c_str(), true));
    ASSERT_TRUE(dk_config_set_is_wb_data(TestEnv::testWorkDir.c_str(), true));

    ASSERT_TRUE(dk_config_enable(TestEnv::testWorkDir.c_str()));
    ASSERT_TRUE(dk_config_is_wb_data(TestEnv::testWorkDir.c_str()));
}