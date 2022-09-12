set(CMAKE_OSX_ARCHITECTURES arm64;x86_64)

set(SRC
    buffer.c
    fuse_darwin.c
    fuse_loop_mt.c
    fuse_opt.c
    helper.c
    mount_darwin.c
    cuse_lowlevel.c
    fuse_kern_chan.c
    fuse_lowlevel.c
    fuse_session.c
    fuse.c
    fuse_loop.c
    fuse_mt.c
    fuse_signals.c
    modules/iconv.c
    modules/subdir.c
    modules/threadid.c
    modules/volicon.c
)

add_library (fuse-t SHARED ${SRC})
set_target_properties(fuse-t PROPERTIES OUTPUT_NAME fuse-t)

add_library (fuse-t-static STATIC ${SRC})
set_target_properties(fuse-t-static PROPERTIES OUTPUT_NAME fuse-t)

set(LIBS "-liconv -framework CoreFoundation -framework DiskArbitration")

add_definitions(-DFUSERMOUNT_DIR="/usr/local/bin")
add_definitions(-D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=26)

target_include_directories (fuse-t PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_include_directories (fuse-t-static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)

target_link_libraries (fuse-t LINK_PUBLIC ${LIBS})
