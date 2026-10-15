cmake_minimum_required(VERSION 3.15)
project(certpp_consumer LANGUAGES CXX)

find_package(certpp 1 REQUIRED CONFIG)

add_executable(certpp_consumer main.cpp)
target_compile_features(certpp_consumer PRIVATE cxx_std_17)
target_link_libraries(certpp_consumer PRIVATE certpp::certpp)
