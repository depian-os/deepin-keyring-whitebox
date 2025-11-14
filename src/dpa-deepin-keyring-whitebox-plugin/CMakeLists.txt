
set(POLKIT_AGNET_PLUGIN_NAME "dpa-deepin-keyring-whitebox-plugin")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS ${DK_COMPILE_FLAGS})

find_package(Qt6 COMPONENTS Core Widgets REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_compile_definitions(DPAEXTGNOMEKEYRING_LIBRARY)

file(GLOB_RECURSE POLKIT_AGNET_PLUGIN_SRCS
    "*.h"
    "*.cpp"
)

add_library(${POLKIT_AGNET_PLUGIN_NAME} MODULE
    ${POLKIT_AGNET_PLUGIN_SRCS}
)
add_dependencies(${POLKIT_AGNET_PLUGIN_NAME} ${CORE_LIB_NAME})
set_target_properties(${POLKIT_AGNET_PLUGIN_NAME} PROPERTIES OUTPUT_NAME "dpa-deepin-keyring-whitebox")
target_include_directories(${POLKIT_AGNET_PLUGIN_NAME} PUBLIC
    ${SRC_BASE_DIR}/core/
)
target_link_libraries(${POLKIT_AGNET_PLUGIN_NAME} PRIVATE
    ${PROJECT_BINARY_DIR}/src/core/libcore.a
    Qt6::Core
    Qt6::Widgets
    Qt6::DBus
)

install(TARGETS ${POLKIT_AGNET_PLUGIN_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/polkit-1-dde/plugins)