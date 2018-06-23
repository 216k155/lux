# Copyright (c) 2018 The Luxcore developers

set(CMAKE_CXX_STANDARD 11)

# Ensure that WINDRES_PREPROC is enabled when using windres.
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    list(APPEND CMAKE_RC_FLAGS "-DWINDRES_PREPROC")
endif()

add_subdirectory(config)
add_subdirectory(crypto)
add_subdirectory(leveldb)
add_subdirectory(secp256k1)
add_subdirectory(univalue)

# Various completely unrelated features shared by all executables.
add_library(util
        chainparamsbase.cpp
        clientversion.cpp
        compat/glibc_sanity.cpp
        compat/glibcxx_sanity.cpp
        compat/strnlen.cpp
        random.cpp
        rpcprotocol.cpp
        sync.cpp
        uint256.cpp
        util.cpp
        utilmoneystr.cpp
        utilstrencodings.cpp
        utiltime.cpp
        )

target_compile_definitions(util PUBLIC HAVE_CONFIG_H)
target_include_directories(util
        PUBLIC
        .
        # To access the config.
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/config
        )

# Dependencies
set(BOOST_PACKAGES_REQUIRED chrono filesystem program_options)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(Boost_USE_STATIC_LIBS ON)
    list(APPEND BOOST_PACKAGES_REQUIRED thread_win32)

    find_package(SHLWAPI REQUIRED)
    target_link_libraries(util ${SHLWAPI_LIBRARY})
    target_include_directories(util PUBLIC ${SHLWAPI_INCLUDE_DIR})

    find_library(WS2_32_LIBRARY NAMES ws2_32)
    target_link_libraries(util ${WS2_32_LIBRARY})
else()
    list(APPEND BOOST_PACKAGES_REQUIRED date_time thread)
endif()

function(prepend var prefix)
    set(listVar "")
    foreach(f ${ARGN})
        list(APPEND listVar "${prefix}${f}")
    endforeach(f)
    set(${var} "${listVar}" PARENT_SCOPE)
endfunction(prepend)

prepend(BOOST_LIBRARIES "Boost::" ${BOOST_PACKAGES_REQUIRED})

find_package(Boost 1.58 REQUIRED ${BOOST_PACKAGES_REQUIRED})
target_link_libraries(util univalue ${BOOST_LIBRARIES})

# More completely unrelated features shared by all executables.
# Because nothing says this is different from util than "common"
add_library(common
addrman.cpp
alert.cpp
bloom.cpp
chain.cpp
checkpoints.cpp
consensus/validation.cpp
init.cpp
leveldbwrapper.cpp
main.cpp
merkleblock.cpp
miner.cpp
net.cpp
noui.cpp
policy/fees.cpp
policy/policy.cpp
pow.cpp
rest.cpp
rpcblockchain.cpp
rpcdarksend.cpp
rpcmining.cpp
rpcmisc.cpp
rpcnet.cpp
rpcrawtransaction.cpp
httprpc.cpp
httpserver.cpp
luxcontrol.cpp
rpcserver.cpp
script/sigcache.cpp
timedata.cpp
txdb.cpp
txmempool.cpp
validationinterface.cpp
versionbits.cpp
lux/luxstate.cpp
lux/luxtransaction.cpp
lux/luxDGP.cpp
lux/storageresults.cpp
        )

target_link_libraries(common util secp256k1)

# lux-cli
option(BUILD_LUX_CLI "Build lux-cli" ON)
if(BUILD_LUX_CLI)
    add_executable(lux-cli lux-cli.cpp rpcclient.cpp)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        target_sources(lux-cli PRIVATE lux-cli-res.rc)
    endif()

    # This require libevent
    find_package(Event REQUIRED)
    target_include_directories(lux-cli PUBLIC ${EVENT_INCLUDE_DIR})
    target_link_libraries(lux-cli common ${EVENT_LIBRARY})
endif()


# lux-seeder
#option(BUILD_LUX_SEEDER "Build lux-seeder" OFF)
#if (BUILD_LUX_SEEDER)
#    add_subdirectory(seeder)
#endif()