
set(LIB_NAME "libdeepin-keyring-whitebox")

set(CMAKE_C_FLAGS ${DK_COMPILE_FLAGS})

file(GLOB_RECURSE LIB_SRCS
    "*.h"
    "*.c"
)

add_library(${LIB_NAME} SHARED
    ${LIB_SRCS}
)
add_dependencies(${LIB_NAME} ${CORE_LIB_NAME})
set_target_properties(${LIB_NAME} PROPERTIES OUTPUT_NAME "deepin-keyring-whitebox" VERSION ${PROJECT_VERSION})
target_include_directories(${LIB_NAME} PUBLIC
    ${SRC_BASE_DIR}/core/
)
target_link_libraries(${LIB_NAME} PRIVATE
    ${PROJECT_BINARY_DIR}/src/core/libcore.a
)

install(TARGETS ${LIB_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${CMAKE_LIBRARY_ARCHITECTURE})
install(FILES deepin_keyring_whitebox.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include)