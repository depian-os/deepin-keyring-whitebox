set(CMAKE_C_FLAGS ${DK_COMPILE_FLAGS})

file(GLOB_RECURSE CORE_LIB_SRCS
    "*.h"
    "*.c"
)

add_library(${CORE_LIB_NAME} STATIC
    ${CORE_LIB_SRCS}
)
