set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(BR2_SDK_PATH /home/mike/workspace/luckfox_ws/luckfox-pico/tools/linux/toolchain/arm-rockchip830-linux-uclibcgnueabihf/)

set(CMAKE_C_COMPILER   ${BR2_SDK_PATH}/bin/arm-rockchip830-linux-uclibcgnueabihf-gcc)
set(CMAKE_CXX_COMPILER ${BR2_SDK_PATH}/bin/arm-rockchip830-linux-uclibcgnueabihf-g++)

set(BR2_SYSROOT ${BR2_SDK_PATH}/arm-rockchip830-linux-uclibcgnueabihf/sysroot/)
set(CMAKE_SYSROOT ${BR2_SYSROOT})

set(ENV{PKG_CONFIG_DIR} "")
set(ENV{PKG_CONFIG_LIBDIR} "${CMAKE_SYSROOT}/usr/lib/pkgconfig:${CMAKE_SYSROOT}/usr/share/pkgconfig")
set(ENV{PKG_CONFIG_SYSROOT_DIR} ${CMAKE_SYSROOT})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --sysroot=${BR2_SYSROOT}" CACHE INTERNAL "" FORCE)
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} --sysroot=${BR2_SYSROOT}" CACHE INTERNAL "" FORCE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --sysroot=${BR2_SYSROOT}" CACHE INTERNAL "" FORCE)
set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} --sysroot=${BR2_SYSROOT}" CACHE INTERNAL "" FORCE)

set(CMAKE_FIND_ROOT_PATH ${BR2_SYSROOT})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

#set(CMAKE_CROSSCOMPILING true)
#if(CMAKE_CROSSCOMPILING)
#  set(ENV{PKG_CONFIG_LIBDIR} ${CMAKE_FIND_ROOT_PATH}/lib/pkgconfig/)
#  include_directories(BEFORE ${CMAKE_FIND_ROOT_PATH}/include)
#endif()

