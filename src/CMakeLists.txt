# Copyright (c) 2018 The Luxcore developers

set(CMAKE_CXX_STANDARD 11)

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
set(BOOST_PACKAGES_REQUIRED filesystem)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(Boost_USE_STATIC_LIBS ON)
    list(APPEND BOOST_PACKAGES_REQUIRED thread_win32)
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

find_package(Boost 1.55 REQUIRED ${BOOST_PACKAGES_REQUIRED})
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
