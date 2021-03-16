cmake_minimum_required(VERSION 3.0)
project(backend CXX)

include_directories(../include)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall")
add_executable(${PROJECT_NAME} main.cpp)
