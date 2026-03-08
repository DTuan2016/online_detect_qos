cmake_minimum_required(VERSION 3.16)
project(online_detect C)

set(CMAKE_C_STANDARD 11)

# =========================
# Paths
# =========================
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INC_DIR ${CMAKE_SOURCE_DIR}/include)
set(BUILD_DIR ${CMAKE_BINARY_DIR})

# =========================
# Find libbpf & libxdp
# =========================
find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBXDP REQUIRED libxdp)

# =========================
# Build BPF program
# =========================

set(BPF_SRC ${SRC_DIR}/xdp_prog_kern.c)
set(BPF_OBJ ${BUILD_DIR}/xdp_prog_kern.o)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND clang
        -O2 -g
        -target bpf
        -D__TARGET_ARCH_x86
	-I/usr/include/aarch64-linux-gnu
        -I${INC_DIR}
        -I${SRC_DIR}
        -c ${BPF_SRC}
        -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling BPF program"
)

add_custom_target(bpf_program ALL DEPENDS ${BPF_OBJ})

# =========================
# Build user-space loader
# =========================

add_executable(xdp_loader
    ${SRC_DIR}/xdp_loader.c
    ${SRC_DIR}/cmd_line.c
)

add_executable(dump_csv
    ${SRC_DIR}/dump_csv.c
)

target_include_directories(xdp_loader PRIVATE
    ${INC_DIR}
    ${SRC_DIR}
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBXDP_INCLUDE_DIRS}
)

target_include_directories(dump_csv PRIVATE
    ${INC_DIR}
    ${SRC_DIR}
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBXDP_INCLUDE_DIRS}
)

target_link_libraries(xdp_loader
    ${LIBBPF_LIBRARIES}
    ${LIBXDP_LIBRARIES}
    elf
    z
)

target_link_libraries(dump_csv
    ${LIBBPF_LIBRARIES}
    elf
    z
)

add_dependencies(xdp_loader bpf_program)

# =========================
# Build TC BPF program
# =========================

set(TC_BPF_SRC ${SRC_DIR}/tc_prog.c)
set(TC_BPF_OBJ ${BUILD_DIR}/tc_prog.o)

add_custom_command(
    OUTPUT ${TC_BPF_OBJ}
    COMMAND clang
        -O2 -g
        -target bpf
        -D__TARGET_ARCH_x86
        -I/usr/include/aarch64-linux-gnu
        -I${INC_DIR}
        -I${SRC_DIR}
        -c ${TC_BPF_SRC}
        -o ${TC_BPF_OBJ}
    DEPENDS ${TC_BPF_SRC}
    COMMENT "Compiling TC BPF program"
)

add_custom_target(tc_bpf_program ALL DEPENDS ${TC_BPF_OBJ})
