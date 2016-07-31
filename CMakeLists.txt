cmake_minimum_required (VERSION 3.1)
project (HTMLConv)
LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")

set (CMAKE_CXX_STANDARD 11)

file(GLOB_RECURSE SOURCES "src/*.cpp")

find_package(TinyXML REQUIRED)

include_directories(. ${TINYXML2_INCLUDE_DIRS})

add_executable(HTMLConv ${SOURCES})
target_link_libraries(HTMLConv ${TINYXML2_LIBRARIES})