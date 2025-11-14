cmake_minimum_required(VERSION 3.13)

project(deepin-keyring-whitebox VERSION 1.0 LANGUAGES C CXX)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX /usr CACHE PATH "/usr" FORCE)
endif()

enable_testing()

add_subdirectory("src")
add_subdirectory("misc")
