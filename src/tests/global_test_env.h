#pragma once

#include <gtest/gtest.h>

class TestEnv : public ::testing::Environment
{
public:
    void SetUp() override;

    void TearDown() override;

    static std::string testWorkDir;
};