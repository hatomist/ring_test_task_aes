cmake_minimum_required(VERSION 3.17)
project(ring_test_task_aes C)

set(CMAKE_C_STANDARD 99)

add_executable(ring_test_task_aes main.c main.h)
find_library(GCRYPT_LIB gcrypt HINTS build/lib)
include_directories(build/include)
target_link_libraries(ring_test_task_aes ${GCRYPT_LIB})
