set(DK_COMPILE_FLAGS "-W -Wall -fstack-protector-strong -D_FORTITY_SOURCE=1 -z noexecstack -pie -fPIC -z lazy")
set(SRC_BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(DK_DEBUG_MODE)
endif()

add_compile_definitions(_GNU_SOURCE)

# core：module的依赖，避免重复代码和重复编译
set(CORE_LIB_NAME "core")
add_subdirectory("core")

# module
add_subdirectory("deepin-keyring-whitebox")
add_subdirectory("pam-deepin-keyring")
add_subdirectory("libdeepin-keyring-whitebox")

# dpa-plugin
add_subdirectory("dpa-deepin-keyring-whitebox-plugin")

add_subdirectory("tests")
