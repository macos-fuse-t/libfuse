add_library (fuse 
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

add_definitions(-DPACKAGE_VERSION="1.0.0")
add_definitions(-DFUSERMOUNT_DIR="/usr/local/bin")
add_definitions(-D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=26)

target_include_directories (fuse PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)