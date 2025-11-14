
set(TEST_NAME "deepin-keyring-whitebox-tests")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS ${DK_COMPILE_FLAGS})

# 用于测试覆盖率的编译条件
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage -lgcov")
find_package(GTest REQUIRED)

file(GLOB_RECURSE TEST_SRCS
    "*.h"
    "*.cpp"
)

add_executable(${TEST_NAME}
    ${TEST_SRCS}
)
add_dependencies(${TEST_NAME} ${CORE_LIB_NAME})
target_include_directories(${TEST_NAME} PUBLIC
    ${SRC_BASE_DIR}/core/
)
target_link_libraries(${TEST_NAME} PRIVATE
    ${PROJECT_BINARY_DIR}/src/core/libcore.a
    ${GTEST_LIBRARIES}
    -lpthread
    -ldl
)

add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} "--gtest_output=xml:${PROJECT_BINARY_DIR}/ut-test-report.xml")