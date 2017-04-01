cmake_minimum_required(VERSION 3.7)
project(cs3423Assign6)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES logprt.c logprt.h prtlog.c)
add_executable(cs3423Assign6 ${SOURCE_FILES})