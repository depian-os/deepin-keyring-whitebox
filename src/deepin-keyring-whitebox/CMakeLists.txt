
set(M_NAME "deepin-keyring-whitebox")

set(CMAKE_C_FLAGS ${DK_COMPILE_FLAGS})

file(GLOB_RECURSE SRCS
    "*.h"
    "*.c"
)

add_executable(${M_NAME}
    ${SRCS}
)
add_dependencies(${M_NAME} ${CORE_LIB_NAME})

target_include_directories(${M_NAME} PUBLIC
    ${SRC_BASE_DIR}/core/
)

target_link_libraries(${M_NAME} PRIVATE
    ${PROJECT_BINARY_DIR}/src/core/libcore.a
    -lpam
    -ldl
)

install(TARGETS ${M_NAME} DESTINATION bin)