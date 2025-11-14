
set(PAM_LIB_NAME "pam_deepin_keyring")

set(CMAKE_C_FLAGS ${DK_COMPILE_FLAGS})

file(GLOB_RECURSE LIB_SRCS
    "*.h"
    "*.c"
)

add_library(${PAM_LIB_NAME} MODULE
    ${LIB_SRCS}
)
add_dependencies(${PAM_LIB_NAME} ${CORE_LIB_NAME})
set_target_properties(${PAM_LIB_NAME} PROPERTIES PREFIX "")
target_include_directories(${PAM_LIB_NAME} PUBLIC
    ${SRC_BASE_DIR}/core/
)
target_link_libraries(${PAM_LIB_NAME} PRIVATE
    ${PROJECT_BINARY_DIR}/src/core/libcore.a
    -lpam
)

install(TARGETS ${PAM_LIB_NAME} DESTINATION lib/${CMAKE_LIBRARY_ARCHITECTURE}/security)