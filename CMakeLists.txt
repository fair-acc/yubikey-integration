cmake_minimum_required(VERSION 3.25)
project(MyJITProject VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# set(CMAKE_BUILD_TYPE Release)

add_executable(inspect src/inspect.cpp)
target_link_libraries(inspect PRIVATE crypto)

add_executable(yk_serial src/yk_serial.cpp)
target_link_libraries(yk_serial PRIVATE ykpiv)

add_executable(yk_encrypt src/yk_encrypt.cpp)
target_link_libraries(yk_encrypt PRIVATE ykpiv crypto)

add_executable(yk_decrypt src/yk_decrypt.cpp)
target_link_libraries(yk_decrypt PRIVATE ykpiv crypto)

add_custom_target(build_all_executables ALL DEPENDS inspect yk_serial yk_encrypt yk_decrypt)
