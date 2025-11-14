#include <gtest/gtest.h>

#include "global_test_env.h"

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    AddGlobalTestEnvironment(new TestEnv());

    return RUN_ALL_TESTS();
}