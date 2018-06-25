# Copyright (c) 2018 The Luxcore developers
cmake_minimum_required(VERSION 3.5)
project(Lux)

set(CMAKE_CXX_STANDARD 11)

# Default visibility is hidden on all targets.
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

option(BUILD_LUX_WALLET "Activate the wallet functionality" ON)
option(BUILD_LUX_ZMQ "Activate the ZeroMQ functionalities" ON)
option(BUILD_LUX_CLI "Build lux-cli" ON)
option(BUILD_LUX_TX "Build lux-tx" ON)
option(BUILD_LUX_QT "Build lux-qt" ON)
#option(BUILD_LUX_SEEDER "Build lux-seeder" ON)

# Ensure that WINDRES_PREPROC is enabled when using windres.
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    list(APPEND CMAKE_RC_FLAGS "-DWINDRES_PREPROC")
endif()

# Enable warning
include(AddCompilerFlags)

add_c_compiler_flag(-Wnested-externs -Wstrict-prototypes)
add_compiler_flag(
        -Wall
        -Wextra
        -Wformat
        -Wvla
        -Wformat-security
        -Wcast-align
)

option(EXTRA_WARNINGS "Enable extra warnings" OFF)
if(EXTRA_WARNINGS)
    add_compiler_flag(-Wshadow)
    add_cxx_compiler_flag(-Wsuggest-override)
else()
    add_compiler_flag(-Wno-unused-parameter)
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

# Target specific configs
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_THREADAPI win32)

    find_package(SHLWAPI REQUIRED)
    target_link_libraries(util ${SHLWAPI_LIBRARY})
    target_include_directories(util PUBLIC ${SHLWAPI_INCLUDE_DIR})

    find_library(WS2_32_LIBRARY NAMES ws2_32)
    target_link_libraries(util ${WS2_32_LIBRARY})
    target_compile_definitions(util PUBLIC BOOST_THREAD_USE_LIB)
endif()

# Boost packages
set(BOOST_PACKAGES_REQUIRED chrono filesystem program_options thread)

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
allocators.cpp
amount.h
chainparamsbase.cpp
coins.cpp
consensus/merkle.cpp
consensus/merkle.h
consensus/params.h
cpp-ethereum/libdevcore/CommonData.cpp
cpp-ethereum/libdevcore/CommonData.h
eccryptoverify.cpp
ecwrapper.cpp
hash.cpp
hash.h
key.cpp
prevector.h
primitives/block.cpp
primitives/block.h
primitives/transaction.cpp
primitives/transaction.h
pubkey.cpp
pubkey.h
random.cpp
script/bitcoinconsensus.cpp
script/interpreter.cpp
script/interpreter.h
script/script.cpp
script/script.h
script/script_error.cpp
script/script_error.h
script/standard.cpp
serialize.h
tinyformat.h
uint256.cpp
uint256.h
util.h
util.cpp
utilmoneystr.cpp
utilstrencodings.cpp
utilstrencodings.h
utiltime.cpp
version.h
        )

target_link_libraries(common util secp256k1)

# libbitcoinconsensus
add_library(bitcoinconsensus
        arith_uint256.cpp
        hash.cpp
        primitives/transaction.cpp
        pubkey.cpp
        script/bitcoinconsensus.cpp
        script/interpreter.cpp
        script/script.cpp
        script/script_error.cpp
        uint256.cpp
        utilstrencodings.cpp
        )

target_link_libraries(bitcoinconsensus common)

# Lux server facilities
add_library(server
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
activemasternode.cpp
bip38.cpp
darksend.cpp
db.cpp
crypter.cpp
instantx.cpp
masternode.cpp
masternodeconfig.cpp
rpcdump.cpp
rpcwallet.cpp
stake.cpp
wallet.cpp
wallet_ismine.cpp
walletdb.cpp
rbf.cpp
        )

############### WALLET ##################

# Lux wallet facilities

# Add Berkeley DB dependency.
find_package(BerkeleyDB REQUIRED)

# Add event dependency. This is only required for evhttp_uridecode
# in rpcwallet.cpp so it may be worth considering using an alternative.
find_package(Event REQUIRED)

add_library(wallet
activemasternode.cpp
bip38.cpp
darksend.cpp
db.cpp
crypter.cpp
instantx.cpp
masternode.cpp
masternodeconfig.cpp
rpcdump.cpp
rpcwallet.cpp
stake.cpp
wallet.cpp
wallet_ismine.cpp
walletdb.cpp
rbf.cpp
        )

target_link_libraries(wallet util univalue ${BDBXX_LIBRARY} ${EVENT_LIBRARY})

target_include_directories(wallet
        PUBLIC
        ${BDBXX_INCLUDE_DIR}
        PRIVATE
        ${EVENT_INCLUDE_DIR}
        )

#######################################################################3

# This require libevent
find_package(Event REQUIRED)

target_include_directories(server
        PRIVATE
        leveldb/helpers/memenv
        ${EVENT_INCLUDE_DIR}
        )

target_link_libraries(server
        ${EVENT_LIBRARY}
        bitcoinconsensus
        leveldb
        memenv
        )

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_link_libraries(server ${EVENT_PTHREAD_LIBRARY})
endif()

# RPC client support
add_library(rpcclient rpcclient.cpp)
target_link_libraries(rpcclient univalue util)

# lux-cli
if(BUILD_LUX_CLI)
    add_executable(lux-cli lux-cli.cpp)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        target_sources(lux-cli PRIVATE lux-cli-res.rc)
    endif()

    # This require libevent
    target_include_directories(lux-cli PRIVATE ${EVENT_INCLUDE_DIR})
    target_link_libraries(lux-cli common rpcclient ${EVENT_LIBRARY})
endif()

# lux-tx
if(BUILD_LUX_TX)
    add_executable(lux-tx lux-tx.cpp)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        target_sources(lux-tx PRIVATE lux-tx-res.rc)
    endif()

    target_link_libraries(lux-tx bitcoinconsensus)
endif()

# bitcoind
add_executable(luxd luxd.cpp)
target_link_libraries(luxd server)
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_sources(luxd PRIVATE luxd-res.rc)
endif()

# Wallet
if(BUILD_LUX_WALLET)
#   add_subdirectory(wallet)
    target_link_libraries(luxd wallet)
endif()

# ZeroMQ
if(BUILD_LUX_ZMQ)
    add_subdirectory(zmq)
    target_link_libraries(luxd zmq)
endif()

# lux-seeder
#if (BUILD_LUX_SEEDER)
#    add_subdirectory(seeder)
#endif()