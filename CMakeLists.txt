cmake_minimum_required(VERSION 3.16)

project(online_detect C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Paths

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INC_DIR ${CMAKE_SOURCE_DIR}/include)
set(BUILD_DIR ${CMAKE_BINARY_DIR})

# Architecture Detection

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
set(BPF_ARCH x86)

elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
set(BPF_ARCH arm64)

else()
message(FATAL_ERROR
"Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

message(STATUS "Host architecture : ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "BPF target arch   : ${BPF_ARCH}")

# pkg-config
# Nếu libbpf được cài vào /usr/lib64/pkgconfig

set(ENV{PKG_CONFIG_PATH}
"/usr/lib64/pkgconfig:$ENV{PKG_CONFIG_PATH}")

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBXDP REQUIRED libxdp)

message(STATUS "libbpf version : ${LIBBPF_VERSION}")
message(STATUS "libxdp version : ${LIBXDP_VERSION}")

# Common BPF flags
set(BPF_CFLAGS
    -O2
    -g
    -target bpf
    -D__TARGET_ARCH_${BPF_ARCH}
    -I${INC_DIR}
    -I${SRC_DIR}
)

# XDP BPF program
set(BPF_SRC ${SRC_DIR}/xdp_prog_kern.c)
set(BPF_OBJ ${BUILD_DIR}/xdp_prog_kern.o)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND clang
    ${BPF_CFLAGS}
    -c ${BPF_SRC}
    -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling XDP BPF program"
)

add_custom_target(
    bpf_program ALL
    DEPENDS ${BPF_OBJ}
)

# TC BPF program
set(TC_BPF_SRC ${SRC_DIR}/tc_prog.c)
set(TC_BPF_OBJ ${BUILD_DIR}/tc_prog.o)

add_custom_command(
    OUTPUT ${TC_BPF_OBJ}
    COMMAND clang
    ${BPF_CFLAGS}
    -c ${TC_BPF_SRC}
    -o ${TC_BPF_OBJ}
    DEPENDS ${TC_BPF_SRC}
    COMMENT "Compiling TC BPF program"
)

add_custom_target(
    tc_bpf_program ALL
    DEPENDS ${TC_BPF_OBJ}
)

# xdp_loader
add_executable(
    xdp_loader
    ${SRC_DIR}/xdp_loader.c
    ${SRC_DIR}/cmd_line.c
)

target_include_directories(
    xdp_loader PRIVATE
    ${INC_DIR}
    ${SRC_DIR}
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBXDP_INCLUDE_DIRS}
)

target_link_directories(
    xdp_loader PRIVATE
    ${LIBBPF_LIBRARY_DIRS}
    ${LIBXDP_LIBRARY_DIRS}
)

target_link_libraries(
    xdp_loader PRIVATE
    ${LIBBPF_LIBRARIES}
    ${LIBXDP_LIBRARIES}
    elf
    z
)

add_dependencies(
    xdp_loader
    bpf_program
)

# dump_csv
add_executable(
    dump_csv
    ${SRC_DIR}/dump_csv.c
)

target_include_directories(
    dump_csv PRIVATE
    ${INC_DIR}
    ${SRC_DIR}
    ${LIBBPF_INCLUDE_DIRS}
)

target_link_directories(
    dump_csv PRIVATE
    ${LIBBPF_LIBRARY_DIRS}
)

target_link_libraries(
    dump_csv PRIVATE
    ${LIBBPF_LIBRARIES}
    elf
    z
)

# Install
install(
    TARGETS
    xdp_loader
    dump_csv
    RUNTIME DESTINATION bin
)
