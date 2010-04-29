#==============================================================================#
#                                                                              #
#  Copyright (c) 2010 maidsafe.net limited                                     #
#  All rights reserved.                                                        #
#                                                                              #
#  Redistribution and use in source and binary forms, with or without          #
#  modification, are permitted provided that the following conditions are met: #
#                                                                              #
#      * Redistributions of source code must retain the above copyright        #
#        notice, this list of conditions and the following disclaimer.         #
#      * Redistributions in binary form must reproduce the above copyright     #
#        notice, this list of conditions and the following disclaimer in the   #
#        documentation and/or other materials provided with the distribution.  #
#      * Neither the name of the maidsafe.net limited nor the names of its     #
#        contributors may be used to endorse or promote products derived from  #
#        this software without specific prior written permission.              #
#                                                                              #
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" #
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  #
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE  #
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR         #
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF        #
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    #
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN     #
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)     #
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  #
#  POSSIBILITY OF SUCH DAMAGE.                                                 #
#                                                                              #
#==============================================================================#
#                                                                              #
#  Written by maidsafe.net team                                                #
#                                                                              #
#  Significant contribution made by Stephan Menzel                             #
#                                                                              #
#==============================================================================#


CMAKE_MINIMUM_REQUIRED(VERSION 2.8 FATAL_ERROR)
MESSAGE("================================================================================\n")
SET(CMAKE_CACHEFILE "${CMAKE_CACHEFILE_DIR}/CMakeCache.txt")
IF(WIN32)
  STRING(REPLACE "/" "\\" CMAKE_CACHEFILE ${CMAKE_CACHEFILE})
ENDIF()

SET(ERROR_MESSAGE "No generator previously specified.  Run:\n")
SET(ERROR_MESSAGE_CMAKE_PATH "cmake ../..")
GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after PROJECT command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"Visual Studio 9 2008\"\n\n")
ELSEIF(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\trm ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"CodeBlocks - Unix Makefiles\"\n\n")
ELSE()
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"CodeBlocks - MinGW Makefiles\"\n\n")
ENDIF()

SET(ERROR_MESSAGE "${ERROR_MESSAGE}To see a full list of generators, run:\n\t${ERROR_MESSAGE_CMAKE_PATH} --help\n")
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF(CMAKE_BUILD_TYPE_DIR MATCHES "Release")
  SET(PROJECT_NAME maidsafe_dht)
ELSE()
  SET(PROJECT_NAME maidsafe_dht_${CMAKE_BUILD_TYPE_DIR})
ENDIF()

# This call resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
PROJECT(${PROJECT_NAME})
SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR})

GET_FILENAME_COMPONENT(${PROJECT_NAME}_ROOT ${${PROJECT_NAME}_SOURCE_DIR} PATH)
SET(${PROJECT_NAME}_SOURCE_DIR ${${PROJECT_NAME}_ROOT}/src)

IF(NOT MAIDSAFE_TEST_TYPE)
  SET(MAIDSAFE_TEST_TYPE "BEH" CACHE STRING "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
ENDIF()

IF(UNIX)
  EXECUTE_PROCESS(COMMAND date +%a%d%m%y OUTPUT_VARIABLE pddate OUTPUT_STRIP_TRAILING_WHITESPACE)
ELSE()
  EXECUTE_PROCESS(COMMAND CMD /C DATE /T OUTPUT_VARIABLE pddate OUTPUT_STRIP_TRAILING_WHITESPACE)
  STRING(REPLACE "/" "" pddate ${pddate})
  STRING(SUBSTRING ${pddate} 0 4 pddateddmm)
  STRING(SUBSTRING ${pddate} 6 2 pddateyy)
  SET(pddate ${pddateddmm}${pddateyy})
ENDIF()

IF(APPLE)
  SET(CMAKE_OSX_SYSROOT "/")
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  MESSAGE("Building a package which is OK to release.")
  MESSAGE("------------------------------------------")
ELSE()
  MESSAGE("Building a package which is NOT OK to release.")
  MESSAGE("----------------------------------------------")
  SET(pddate "DEVELOPER_${pddate}")
ENDIF()


# setup a single target path for libraries and executables -
# this avoids copying all the dlls and exes together
UNSET(CMAKE_RUNTIME_OUTPUT_DIRECTORY CACHE)
UNSET(CMAKE_LIBRARY_OUTPUT_DIRECTORY CACHE)
UNSET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY CACHE)
IF(MSVC)
  IF(CMAKE_CL_64)
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Executable target dir (x64).")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Shared library target dir (x64).")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Static library target dir (x64).")
  ELSE()
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Executable target dir (win32).")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Shared library target dir (win32).")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Static library target dir (win32).")
  ENDIF()
ELSE()
  SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Executable target dir.")
  SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Shared library target dir.")
  SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Static library target dir.")
ENDIF()

SET(CMAKE_DEBUG_POSTFIX _d)
SET(CMAKE_RELWITHDEBINFO_POSTFIX _rwdi)
SET(CMAKE_MINSIZEREL_POSTFIX _msr)

###################################################################################################
# Set default directories to be searched for included files and libs                              #
###################################################################################################
IF(DEFINED ADD_LIBRARY_DIR)
  IF(DEFAULT_LIBRARY_DIR)
    LIST(REMOVE_DUPLICATES DEFAULT_LIBRARY_DIR)
  ENDIF()
  SET(DEFAULT_LIBRARY_DIR ${DEFAULT_LIBRARY_DIR} ${ADD_LIBRARY_DIR} CACHE PATH "Path to libraries directories" FORCE)
ENDIF()

IF(MSVC)
  SET(CMAKE_INCLUDE_PATH "c:\\msvc\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\msvc\\lib" ${DEFAULT_LIBRARY_DIR})
ELSEIF(WIN32)
  SET(CMAKE_INCLUDE_PATH "c:\\usr\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\usr\\lib" ${DEFAULT_LIBRARY_DIR})
ELSE()
  SET(CMAKE_INCLUDE_PATH "/usr/include")
  SET(CMAKE_LIBRARY_PATH "/usr/lib" ${DEFAULT_LIBRARY_DIR})
ENDIF()

###################################################################################################
# Boost libraries search                                                                          #
###################################################################################################
SET(REQUIRED_BOOST_COMPONENTS date_time filesystem program_options regex system thread)
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindBoost.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Boost_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Boost_LIBRARY_DIRS})

###################################################################################################
# Google Glog library (logging) search. Only on UNIX, since currently it cannot be compiled on    #
# Windows with MinGW                                                                              #
###################################################################################################
INCLUDE(CheckIncludeFileCXX)
IF(UNIX)
  UNSET(GLOG_LIB CACHE)
  UNSET(GLOG_INCLUDE CACHE)
  SET(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} "${GLOG_ROOT}/include")
  FIND_LIBRARY(GLOG_LIB NAMES libglog.a glog
               PATHS "${GLOG_ROOT}/lib"
               DOC "Path to glog library${DOC_LIB_DIR}")
  CHECK_INCLUDE_FILE_CXX(glog/logging.h GLOG_INCLUDE)
  IF(GLOG_LIB AND GLOG_INCLUDE)
    SET(HAVE_GLOG GLOG_LIB)
    MESSAGE("Using GLOG")
    IF(GLOG_ROOT)
      SET(INCLUDE_DIRS ${INCLUDE_DIRS} "${GLOG_ROOT}/include")
      SET(LIBS_DIRS ${LIBS_DIRS} "${GLOG_ROOT}/lib")
    ENDIF()
  ELSE()
    SET(GLOG_LIB "")
    MESSAGE("Not using GLOG")
    MESSAGE("If installed run ${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_ROOT=<The root directory of glog install prefix>")
    MESSAGE(" You can download it at http://code.google.com/p/google-glog\n")
  ENDIF()
ENDIF()

###################################################################################################
# Google Test library search                                                                      #
###################################################################################################
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindGtest.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gtest_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Gtest_LIBRARY_DIR} ${Gtest_LIBRARY_DIR_DEBUG})


#  IF(APPLE)
#    GET_FILENAME_COMPONENT(LIB_PATH ${Gtest_LIBRARY} PATH)
#    SET(LIBS_DIRS ${LIBS_DIRS} ${LIB_PATH})
#    SET(Gtest_LIBRARY "gtest")
#  ENDIF()


###################################################################################################
# Protocol Buffers library search                                                                 #
###################################################################################################
FILE(GLOB PROTO_FILES RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/protobuf/*.proto")
FILE(GLOB TEST_PROTO_FILES RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/tests/rpcprotocol/*.proto")
SET(PROTO_FILES ${PROTO_FILES} ${TEST_PROTO_FILES})
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindProtobuf.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Protobuf_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Protobuf_LIBRARY_DIR} ${Protobuf_LIBRARY_DIR_DEBUG})

#  IF(APPLE)
#    SET(Protobuf_LIBRARY protobuf)
#  ENDIF()

###################################################################################################
# Python library search                                                                           #
###################################################################################################
UNSET(PYTHON_EXECUTABLE CACHE)
INCLUDE(FindPythonInterp)
INCLUDE(FindPythonLibs)
FIND_PACKAGE(PythonInterp)
IF(PYTHONINTERP_FOUND)
  MESSAGE("-- Found python executable: style checking enabled.")
ELSE()
  MESSAGE("-- Didn't find python executable: style checking disabled.")
ENDIF()

###################################################################################################
# All other libraries search                                                                      #
###################################################################################################
IF(UNIX)
  SET(SYS_LIB dl pthread)
  IF(NOT APPLE)
    SET(SYS_LIB rt c m ${SYS_LIB})
  ENDIF()
ELSEIF(WIN32)
  IF(MSVC)
    SET(SYS_LIB ws2_32 odbc32 odbccp32 WSock32 IPHlpApi)
  ELSE()
    SET(SYS_LIB advapi32 kernel32 ws2_32 iphlpapi mswsock)
  ENDIF()
ENDIF()
FOREACH(library ${SYS_LIB})
  FIND_LIBRARY(CURRENT_LIB ${library})
  IF(CURRENT_LIB)
    MESSAGE("-- Found library ${CURRENT_LIB}")
    GET_FILENAME_COMPONENT(CURRENT_LIBRARY_DIR ${CURRENT_LIB} PATH)
    SET(LIBS_DIRS ${LIBS_DIRS} ${CURRENT_LIBRARY_DIR})
  ELSE()
    SET(ERROR_MESSAGE "\nCould not find library ${library}.  Run\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DADD_LIBRARY_DIR=<Path to ${library} directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
  UNSET(CURRENT_LIB CACHE)
ENDFOREACH()

IF(MSVC)
  SET(SYS_LIB ${SYS_LIB} ${GLOG_LIB})
ELSE()
  SET(SYS_LIB ${SYS_LIB} ${GLOG_LIB} ${Protobuf_LIBRARY})
ENDIF()

SET(LIBS_DIRS ${LIBS_DIRS} ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
LIST(REMOVE_DUPLICATES LIBS_DIRS)
IF(MSVC)
  LINK_DIRECTORIES(${LIBS_DIRS})
ENDIF()

INCLUDE_DIRECTORIES(${${PROJECT_NAME}_SOURCE_DIR})
LIST(REMOVE_DUPLICATES INCLUDE_DIRS)
INCLUDE_DIRECTORIES(AFTER SYSTEM ${INCLUDE_DIRS})

MESSAGE("================================================================================")

IF(MSVC)
  SET(CMAKE_CXX_FLAGS "")
  SET(CMAKE_CXX_FLAGS_INIT "")
  SET(CMAKE_CXX_FLAGS_RELEASE "")
  SET(CMAKE_CXX_FLAGS_DEBUG "")
ENDIF()

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
LIST(APPEND M_LIBUPNP_DIR
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/igd_desc_parse.c
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/minixml.c
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/minisoap.c
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/miniwget.c
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/upnpcommands.c
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/upnpreplyparse.c
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/upnperrors.c
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/miniupnpc.c
       ${${PROJECT_NAME}_SOURCE_DIR}/libupnp/minissdpc.c)
FILE(GLOB M_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/nat-pmp/*.c*"
                       "${${PROJECT_NAME}_SOURCE_DIR}/nat-pmp/*.h*")
FILE(GLOB M_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/upnp/*.c*"
                     "${${PROJECT_NAME}_SOURCE_DIR}/upnp/*.h*")
LIST(REMOVE_ITEM M_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/upnp/upnpclientimpl.cc")
LIST(REMOVE_ITEM M_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/upnp/upnpclientimpl.h")
FILE(GLOB M_PROTOBUF_DIR "${${PROJECT_NAME}_SOURCE_DIR}/protobuf/*.c*"
                         "${${PROJECT_NAME}_SOURCE_DIR}/protobuf/*.h*")
FILE(GLOB M_BASE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/base/*.c*"
                     "${${PROJECT_NAME}_SOURCE_DIR}/base/*.h*")
FILE(GLOB M_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/kademlia/*.c*"
                         "${${PROJECT_NAME}_SOURCE_DIR}/kademlia/*.h*")
SET(STYLE_KADEMLIA ${M_KADEMLIA_DIR})
FILE(GLOB M_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/rpcprotocol/*.c*"
                         "${${PROJECT_NAME}_SOURCE_DIR}/rpcprotocol/*.h*")
SET(STYLE_RPCPROTO ${M_RPCPROTO_DIR})
FILE(GLOB M_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/transport/*.c*"
                          "${${PROJECT_NAME}_SOURCE_DIR}/transport/*.h*")
FILE(GLOB MAIDSAFE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/*.c*"
                       "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/*.h*")
####    TESTS    ####
FILE(GLOB T_BASE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/base/*.c*"
                     "${${PROJECT_NAME}_SOURCE_DIR}/tests/base/*.h*")
FILE(GLOB T_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/kademlia/*.c*"
                         "${${PROJECT_NAME}_SOURCE_DIR}/tests/kademlia/*.h*")
LIST(REMOVE_ITEM T_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/kademlia/testknode.cc")
FILE(GLOB T_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/transport/*.c*"
                          "${${PROJECT_NAME}_SOURCE_DIR}/tests/transport/*.h*")
FILE(GLOB T_MAIN "${${PROJECT_NAME}_SOURCE_DIR}/tests/main.cc"
                 "${${PROJECT_NAME}_SOURCE_DIR}/tests/validationimpl.h")
FILE(GLOB T_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/rpcprotocol/*.c*"
                         "${${PROJECT_NAME}_SOURCE_DIR}/tests/rpcprotocol/*.h*")
SET(STYLE_RPCPROTO_DIR ${T_RPCPROTO_DIR})
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/rpcprotocol/testservices.pb.h")
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/rpcprotocol/testservices.pb.cc")
FILE(GLOB T_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/nat-pmp/*.c*"
                       "${${PROJECT_NAME}_SOURCE_DIR}/tests/nat-pmp/*.h*")
FILE(GLOB T_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/upnp/*.c*"
                     "${${PROJECT_NAME}_SOURCE_DIR}/tests/upnp/*.h*")
FILE(GLOB T_FUNC_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/functionalkademlia/*.c*"
                              "${${PROJECT_NAME}_SOURCE_DIR}/tests/functionalkademlia/*.h*")
LIST(REMOVE_ITEM T_FUNC_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/kademlia/testknode.cc")
FILE(GLOB T_DEMO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/demo/*.c*"
                     "${${PROJECT_NAME}_SOURCE_DIR}/tests/demo/*.h*")
FILE(GLOB T_BENCHMARK_DIR "${${PROJECT_NAME}_SOURCE_DIR}/tests/benchmark/*.c*"
                          "${${PROJECT_NAME}_SOURCE_DIR}/tests/benchmark/*.h*")
LIST(APPEND DHT_SOURCE_FILES ${M_BASE_DIR} ${M_KADEMLIA_DIR} ${M_TRANSPORT_DIR} ${M_PROTOBUF_DIR} ${M_RPCPROTO_DIR} ${M_LIBUPNP_DIR} ${M_UPNP_DIR} ${M_NATPMP_DIR} ${MAIDSAFE_DIR})
###################################################################################################
# Traverse subdirs for imported 3rd party libs                                                    #
###################################################################################################
ADD_SUBDIRECTORY(${${PROJECT_NAME}_SOURCE_DIR}/udt ${CMAKE_BINARY_DIR}/udt)
ADD_SUBDIRECTORY(${${PROJECT_NAME}_SOURCE_DIR}/cryptopp ${CMAKE_BINARY_DIR}/cryptopp)

###################################################################################################
# All Platforms:  Add Test Exes and Create all maidsafe_dht libs                                  #
###################################################################################################
ADD_EXECUTABLE(TESTbase ${T_MAIN} ${T_BASE_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTkademlia ${T_MAIN} ${T_KADEMLIA_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTknode "${${PROJECT_NAME}_SOURCE_DIR}/tests/kademlia/testknode.cc" ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTtransport ${T_MAIN} ${T_TRANSPORT_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTrpcprotocol ${T_MAIN} ${T_RPCPROTO_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTnatpmp ${T_MAIN} ${T_NATPMP_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTupnp ${T_MAIN} ${T_UPNP_DIR} ${MAIDSAFE_H})
# Need to use __declspec(dllimport) in all API header files before linking to SHARED library target
#ADD_EXECUTABLE(kaddemo ${T_DEMO_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(kaddemo_static ${T_DEMO_DIR} ${MAIDSAFE_H})
#ADD_EXECUTABLE(benchmark ${T_BENCHMARK_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(benchmark_static ${T_BENCHMARK_DIR} ${MAIDSAFE_H})

# Force renaming of exes to match standard CMake library renaming policy
SET_TARGET_PROPERTIES(TESTbase PROPERTIES
                        DEBUG_OUTPUT_NAME TESTbase${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME TESTbase${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME TESTbase${CMAKE_MINSIZEREL_POSTFIX})
SET_TARGET_PROPERTIES(TESTkademlia PROPERTIES
                        DEBUG_OUTPUT_NAME TESTkademlia${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME TESTkademlia${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME TESTkademlia${CMAKE_MINSIZEREL_POSTFIX})
SET_TARGET_PROPERTIES(TESTknode PROPERTIES
                        DEBUG_OUTPUT_NAME TESTknode${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME TESTknode${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME TESTknode${CMAKE_MINSIZEREL_POSTFIX})
SET_TARGET_PROPERTIES(TESTtransport PROPERTIES
                        DEBUG_OUTPUT_NAME TESTtransport${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME TESTtransport${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME TESTtransport${CMAKE_MINSIZEREL_POSTFIX})
SET_TARGET_PROPERTIES(TESTrpcprotocol PROPERTIES
                        DEBUG_OUTPUT_NAME TESTrpcprotocol${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME TESTrpcprotocol${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME TESTrpcprotocol${CMAKE_MINSIZEREL_POSTFIX})
SET_TARGET_PROPERTIES(TESTnatpmp PROPERTIES
                        DEBUG_OUTPUT_NAME TESTnatpmp${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME TESTnatpmp${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME TESTnatpmp${CMAKE_MINSIZEREL_POSTFIX})
SET_TARGET_PROPERTIES(TESTupnp PROPERTIES
                        DEBUG_OUTPUT_NAME TESTupnp${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME TESTupnp${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME TESTupnp${CMAKE_MINSIZEREL_POSTFIX})
SET_TARGET_PROPERTIES(kaddemo_static PROPERTIES
                        DEBUG_OUTPUT_NAME kaddemo_static${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME kaddemo_static${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME kaddemo_static${CMAKE_MINSIZEREL_POSTFIX})
SET_TARGET_PROPERTIES(benchmark_static PROPERTIES
                        DEBUG_OUTPUT_NAME benchmark_static${CMAKE_DEBUG_POSTFIX}
                        RELWITHDEBINFO_OUTPUT_NAME benchmark_static${CMAKE_RELWITHDEBINFO_POSTFIX}
                        MINSIZEREL_OUTPUT_NAME benchmark_static${CMAKE_MINSIZEREL_POSTFIX})

# Need to use __declspec(dllexport) in all API header files before adding SHARED library target
#ADD_LIBRARY(maidsafe_dht SHARED ${DHT_SOURCE_FILES})
ADD_LIBRARY(maidsafe_dht_static STATIC ${DHT_SOURCE_FILES})

#Rename maidsafe_dht_static as maidsafe_dht on way out NOT in MSVC names clash of static and import lib
#IF(NOT MSVC)
  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES OUTPUT_NAME maidsafe_dht)
#ENDIF()

###################################################################################################
# Builds                                                                                          #
###################################################################################################
ADD_DEFINITIONS(-DSTATICLIB)
IF(HAVE_GLOG)
  ADD_DEFINITIONS(-DHAVE_GLOG)
ENDIF()
#Ensure we pick up correct libs and not some older installed one
IF(MSVC)
#  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.lib)
#  SET_TARGET_PROPERTIES(maidsafe_dht PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.dll)
#  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES IMPORTED_LOCATION bin/libcryptopp.lib)
#  SET_TARGET_PROPERTIES(cryptopp PROPERTIES IMPORTED_LOCATION bin/libcryptopp.dll)
#  SET_TARGET_PROPERTIES(udt_static PROPERTIES IMPORTED_LOCATION bin/libudt.lib)
#  SET_TARGET_PROPERTIES(udt PROPERTIES  IMPORTED_LOCATION bin/libudt.dll)
ELSE()
  IF(WIN32)
#    SET_TARGET_PROPERTIES(maidsafe_dht PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.dll)
#    SET_TARGET_PROPERTIES(cryptopp PROPERTIES IMPORTED_LOCATION bin/libcryptopp.dll)
#    SET_TARGET_PROPERTIES(udt PROPERTIES IMPORTED_LOCATION bin/libudt.dll)
  ELSE()
#    SET_TARGET_PROPERTIES(maidsafe_dht PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.so)
#    SET_TARGET_PROPERTIES(cryptopp PROPERTIES IMPORTED_LOCATION bin/libcryptopp.so)
#    SET_TARGET_PROPERTIES(udt PROPERTIES IMPORTED_LOCATION bin/libudt.so)
  ENDIF()
  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.a)
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES IMPORTED_LOCATION bin/libcryptopp.a)
  SET_TARGET_PROPERTIES(udt_static PROPERTIES IMPORTED_LOCATION bin/libudt.a)
ENDIF()

IF(NOT MSVC)
  SET(SYS_LIB ${SYS_LIB} ${Boost_LIBRARIES})
  TARGET_LINK_LIBRARIES(TESTbase maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTtransport maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTknode maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTupnp maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
#  IF(WIN32)
#    TARGET_LINK_LIBRARIES(maidsafe_dht "-Wl,--enable-auto-import" udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(kaddemo "-Wl,--enable-auto-import" maidsafe_dht udt cryptopp)
#    TARGET_LINK_LIBRARIES(benchmark "-Wl,--enable-auto-import" maidsafe_dht udt cryptopp)
#  ELSEIF(APPLE)
#    TARGET_LINK_LIBRARIES(maidsafe_dht udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(benchmark maidsafe_dht udt cryptopp ${SYS_LIB})
#  ELSE()
#    TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(benchmark maidsafe_dht udt cryptopp ${SYS_LIB})
#  ENDIF()
  TARGET_LINK_LIBRARIES(kaddemo_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})  
  TARGET_LINK_LIBRARIES(benchmark_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  ADD_DEFINITIONS(-DDEBUG)
ENDIF()

IF(WIN32)
  ADD_DEFINITIONS(-DWIN32 -D_WIN32 -D__WINDOWS__ -D__WIN32__)
ENDIF()

IF(MSVC)
  ADD_DEFINITIONS(-D__MSVC__ -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x501)
  ADD_DEFINITIONS(-D_CONSOLE -D_UNICODE -DUNICODE -D_BIND_TO_CURRENT_VCLIBS_VERSION=1)

  # prevents std::min() and std::max() to be overwritten
  ADD_DEFINITIONS(-DNOMINMAX)

  # prevents from automatic linking of boost libraries
  ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB)

  # warning 4503 disabled due to excessive generation through use of Boost multi_index
  SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Ot /Oy /GL /D \"NDEBUG\" /EHsc /MD /Gy /W3 /Zi /wd4503")
  SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Ot /Oy /D \"_DEBUG\" /EHsc /MDd  /c /ZI /TP /wd4503")
  SET(CMAKE_CXX_FLAGS_MINSIZEREL "/EHsc /MD")
  SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/EHsc /MD")

  # CMake defaults stack size to 10MB.  Set this to windows default of 1MB
  STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
  STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")

  # defining UDT_STATIC prevents declaring __declspec for UDT API functions
  SET_TARGET_PROPERTIES(maidsafe_dht_static TESTbase TESTkademlia TESTknode TESTnatpmp TESTrpcprotocol TESTtransport TESTupnp kaddemo_static benchmark_static PROPERTIES
      COMPILE_FLAGS "-DUDT_STATIC"
      LINK_FLAGS "/STACK:1048576"
      LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG")

  SET(DEBUG_LIBS ${Protobuf_LIBRARY_DEBUG} ${Boost_DATE_TIME_LIBRARY_DEBUG} ${Boost_FILESYSTEM_LIBRARY_DEBUG} ${Boost_THREAD_LIBRARY_DEBUG}
      ${Boost_PROGRAM_OPTIONS_LIBRARY_DEBUG} ${Boost_SYSTEM_LIBRARY_DEBUG} ${Boost_REGEX_LIBRARY_DEBUG})
  SET(RELEASE_LIBS ${Protobuf_LIBRARY} ${Boost_DATE_TIME_LIBRARY_RELEASE} ${Boost_FILESYSTEM_LIBRARY_RELEASE} ${Boost_THREAD_LIBRARY_RELEASE}
      ${Boost_PROGRAM_OPTIONS_LIBRARY_RELEASE} ${Boost_SYSTEM_LIBRARY_RELEASE} ${Boost_REGEX_LIBRARY_RELEASE})

  TARGET_LINK_LIBRARIES(TESTbase maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTknode maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTtransport maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTupnp maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(kaddemo_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(benchmark_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})

#  TARGET_LINK_LIBRARIES(maidsafe_dht udt_static cryptopp_static iphlpapi.lib)
#  TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
#  TARGET_LINK_LIBRARIES(benchmark maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})

  FOREACH (DLIB ${DEBUG_LIBS})
    TARGET_LINK_LIBRARIES(TESTbase debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTkademlia debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTknode debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTnatpmp debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTrpcprotocol debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTtransport debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTupnp debug ${DLIB})
    TARGET_LINK_LIBRARIES(kaddemo_static debug ${DLIB})
    TARGET_LINK_LIBRARIES(benchmark_static debug ${DLIB})
#    TARGET_LINK_LIBRARIES(maidsafe_dht debug ${DLIB})
#    TARGET_LINK_LIBRARIES(kaddemo debug ${DLIB})
#    TARGET_LINK_LIBRARIES(benchmark debug ${DLIB})
  ENDFOREACH()
  TARGET_LINK_LIBRARIES(TESTbase debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTkademlia debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTknode debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTnatpmp debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTtransport debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTupnp debug ${Gtest_LIBRARY_DEBUG})

  FOREACH(RLIB ${RELEASE_LIBS})
    TARGET_LINK_LIBRARIES(TESTbase optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTkademlia optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTknode optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTnatpmp optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTrpcprotocol optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTtransport optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTupnp optimized ${RLIB})
    TARGET_LINK_LIBRARIES(kaddemo_static optimized ${RLIB})
    TARGET_LINK_LIBRARIES(benchmark_static optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(maidsafe_dht optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(kaddemo optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(benchmark optimized ${RLIB})
  ENDFOREACH()
  TARGET_LINK_LIBRARIES(TESTbase optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTkademlia optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTknode optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTnatpmp optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTtransport optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTupnp optimized ${Gtest_LIBRARY})
ENDIF()

####APPLE##############################
IF(APPLE)
  SET(CMAKE_AR "/usr/bin/libtool")
  SET(CMAKE_CXX_CREATE_STATIC_LIBRARY "<CMAKE_AR> -static -o <TARGET> <LINK_FLAGS> <OBJECTS>" "<CMAKE_RANLIB> <TARGET>")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DARWIN_C_SOURCE")
  ADD_DEFINITIONS(-DMAIDSAFE_APPLE -DBSD)
  SET(MAIDSAFE_DHT_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finline-functions -funswitch-loops -fgcse-after-reload -ftree-vectorize -D_FORTIFY_SOURCE=2 -D__FreeBSD__=10 -D_FILE_OFFSET_BITS=64")
  SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wuninitialized -O")
  SET(MAIDSAFE_DHT_CXX_FLAGS "-w")
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES LINK_FLAGS "-pg -fprofile-arcs -ftest-coverage")
  ENDIF()
  SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}" CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov" CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -lgcov" CACHE INTERNAL "" FORCE)
######LINUX################################
ELSEIF(UNIX AND NOT APPLE)
  ADD_DEFINITIONS(-DMAIDSAFE_LINUX)
  SET(MAIDSAFE_DHT_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -fPIC -Wl,-z,relro -Wformat  -Wno-system-headers  -Wformat-security -Wall -finline-functions -funswitch-loops -fgcse-after-reload -ftree-vectorize -fpredictive-commoning -Wextra -Wfloat-equal -Wlong-long -Wredundant-decls -Wstrict-overflow=5 -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -std=c++98 -ansi -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
  SET(MAIDSAFE_DHT_CXX_FLAGS_DEBUG "${MAIDSAFE_DHT_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG}")
  SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${MAIDSAFE_DHT_CXX_FLAGS} ${CMAKE_CXX_FLAGS_RELEASE}  -Wuninitialized -O")
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES LINK_FLAGS "-pg -fprofile-arcs -ftest-coverage")
  ENDIF()
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov" CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -lgcov" CACHE INTERNAL "" FORCE)
  SET(SILENT_BUILD "-w -fPIC -DNDEBUG -O3 -march=native -mtune=native -pipe")
#######WINDOWS##############
ELSEIF(WIN32 AND NOT MSVC)
  ADD_DEFINITIONS(-D__MINGW__ -DWIN32_LEAN_AND_MEAN -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE)
  SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wuninitialized -O")
  SET(MAIDSAFE_DHT_CXX_FLAGS "-Wall -finline-functions -Wextra -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -Wunused-function -Wunused-parameter -Wunused-label -Wunused-value -Wunused-variable -Wwrite-strings -Wno-deprecated -Woverloaded-virtual -D_WIN32_WINNT=0x0501 -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG -DWIN32_LEAN_AND_MEAN -D__MINGW__  -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32 -D_WIN32_WINNT=0x0501")
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp PROPERTIES LINK_FLAGS "-lgcov -pg -fprofile-arcs -ftest-coverage")
  ENDIF()

  SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp kaddemo_static benchmark_static PROPERTIES LINK_FLAGS "-mthreads ")
  SET(SILENT_BUILD  "-w -finline-functions -O3 -DNDEBUG -D_WIN32_WINNT=0x0501 -D_WIN32")
ENDIF()

IF(NOT MSVC)
  SET(CMAKE_CXX_FLAGS "")
  SET(CMAKE_CXX_FLAGS_RELEASE "")
  SET(CMAKE_CXX_FLAGS_DEBUG "")
  IF(CMAKE_BUILD_TYPE MATCHES "Release")
    SET(MAIDSAFE_DHT_CXX_FLAGS "${MAIDSAFE_DHT_CXX_FLAGS} ${MAIDSAFE_DHT_CXX_FLAGS_RELEASE}")
  ELSE()
    SET(MAIDSAFE_DHT_CXX_FLAGS "${MAIDSAFE_DHT_CXX_FLAGS} ${MAIDSAFE_DHT_CXX_FLAGS_DEBUG}")
  ENDIF()
  SET_SOURCE_FILES_PROPERTIES(${DHT_SOURCE_FILES} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_BASE_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_TRANSPORT_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_RPCPROTO_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_UPNP_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_NATPMP_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_DEMO_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_BENCHMARK_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_TARGET_PROPERTIES(TESTkademlia TESTknode PROPERTIES COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/base/crypto.cc PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/base/utils.cc PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES("*boost/*" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES("*google/protobuf/repeated_field.h" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES(${M_PROTOBUF_DIR} PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES("${M_UPNP_DIR}" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES(${M_LIBUPNP_DIR} PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS}")
ENDIF()

###################################################################################################
# Tests                                                                                           #
###################################################################################################
INCLUDE(CTest)
SET(CTEST_CUSTOM_MAXIMUM_PASSED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CUSTOM_MAXIMUM_FAILED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CONTINUOUS_DURATION 600)
SET(CTEST_CONTINUOUS_MINIMUM_INTERVAL 10)
SET(CTEST_START_WITH_EMPTY_BINARY_DIRECTORY true)
IF(PYTHONINTERP_FOUND)
  IF(UNIX)
    ADD_TEST(STYLE_CHECK_KAD ../../tools/cpplint.py ${STYLE_KADEMLIA} ${T_KADEMLIA_DIR} ${T_FUNC_KADEMLIA_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_KAD PROPERTY LABELS Functional Kademlia CodingStyle)
    ADD_TEST(STYLE_CHECK_BASE ../../tools/cpplint.py ${M_BASE_DIR} ${T_BASE_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_BASE PROPERTY LABELS Functional Base CodingStyle)
    ADD_TEST(STYLE_CHECK_RPC ../../tools/cpplint.py ${M_RPCPROTO_DIR} ${STYLE_RPCPROTO_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_RPC PROPERTY LABELS Functional RpcProtocol CodingStyle)
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${${PROJECT_NAME}_ROOT})
    ADD_TEST(STYLE_CHECK ../../tools/run_cpplint.bat ${STYLE_CHECK_SOURCE})
    SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
  ENDIF()
ENDIF()
SET(FOUNDALLTESTS true)
IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET(TEST_POSTFIX ${CMAKE_DEBUG_POSTFIX})
ELSEIF(CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
  SET(TEST_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX})
ELSEIF(CMAKE_BUILD_TYPE MATCHES "MinSizeRel")
  SET(TEST_POSTFIX ${CMAKE_MINSIZEREL_POSTFIX})
ENDIF()

SET(TEST_EXES TESTupnp TESTnatpmp TESTbase TESTknode TESTkademlia TESTtransport TESTrpcprotocol)
FOREACH(TEST_EXE ${TEST_EXES})
  IF(MSVC)
    SET(TEST_EXECUTABLES ${TEST_EXECUTABLES} ${CMAKE_BUILD_TYPE}/${TEST_EXE}${TEST_POSTFIX}.exe)
  ELSEIF(WIN32)
    SET(TEST_EXECUTABLES ${TEST_EXECUTABLES} ${TEST_EXE}${TEST_POSTFIX}.exe)
  ELSE()
    SET(TEST_EXECUTABLES ${TEST_EXECUTABLES} ${TEST_EXE}${TEST_POSTFIX})
  ENDIF()
ENDFOREACH()

FOREACH(TEST_EXECUTABLE ${TEST_EXECUTABLES})
  IF(NOT EXISTS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE})
    IF(FOUNDALLTESTS)
      SET(FOUNDALLTESTS false)
      MESSAGE("")
      MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
      MESSAGE("")
    ENDIF()
    MESSAGE(WARNING "Cannot find ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE}")
  ELSE()
    EXECUTE_PROCESS(COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE} --gtest_list_tests OUTPUT_VARIABLE maid_tests)
    STRING(REPLACE "\n" ";" maid_tests "${maid_tests}")
    STRING(REPLACE " " "" maid_tests "${maid_tests}")
    IF(NOT WIN32)
      STRING(REPLACE " " ";" TEST_EXECUTABLE "${TEST_EXECUTABLE}")
    ENDIF()
    FOREACH(tst ${maid_tests})
      IF(NOT "${tst}" MATCHES [_])
        STRING(REGEX REPLACE "Test" "" label_name ${tst})
        STRING(REPLACE "." "" label_name ${label_name})
      ENDIF()
      IF(NOT "${tst}" MATCHES "(profiling).+" AND NOT "${tst}" MATCHES "Mergemismatchforsummaries+")
        IF(NOT "${tst}" MATCHES "(\\.$)")
          IF("${tst}" MATCHES "(${MAIDSAFE_TEST_TYPE}).+")
            SET(all_tests ${all_tests} ${tst})
            ADD_TEST(${tst} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE} --gtest_filter=*${tst}*)
            IF("${tst}" MATCHES "^FUNC_" OR "${tst}" MATCHES "^DISABLED_FUNC_")
              SET_PROPERTY(TEST ${tst} PROPERTY LABELS Functional ${label_name} ${CMAKE_BUILD_TYPE})
              SET_PROPERTY(TEST ${tst} PROPERTY TIMEOUT 600)
            ELSEIF("${tst}" MATCHES "^BEH_" OR "${tst}" MATCHES "^DISABLED_BEH_")
              SET_PROPERTY(TEST ${tst} PROPERTY LABELS Behavioural ${label_name} ${CMAKE_BUILD_TYPE})
              SET_PROPERTY(TEST ${tst} PROPERTY TIMEOUT 60)
            ELSE()
              MESSAGE("")
              MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
              MESSAGE("")
              MESSAGE(AUTHOR_WARNING "${tst} should be named \"BEH_...\" or \"FUNC_...\" (with an optional \"DISABLED_\" prepended).")
              MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            ENDIF()
            EXECUTE_PROCESS(COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE} --gtest_list_tests --gtest_filter=*${tst}* OUTPUT_VARIABLE repeateds)
            STRING(REGEX MATCHALL "\n" repeats ${repeateds})
            LIST(LENGTH repeats count)
            IF(count GREATER 2)
              SET(repeated_tests ${repeated_tests} ${tst})
            ENDIF()
          ENDIF()
        ENDIF()
      ENDIF()
    ENDFOREACH()
  ENDIF()
ENDFOREACH()
IF(NOT FOUNDALLTESTS)
  MESSAGE("Run cmake again after make to pick up tests.\n")
  MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
ENDIF()

IF(NOT CMAKE_SUPPRESS_DEVELOPER_WARNINGS AND DEFINED repeated_tests)
  SET(WARNING_MESSAGE "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
  FOREACH(var ${repeated_tests})
    SET(WARNING_MESSAGE "${WARNING_MESSAGE}\nRepeated test name - ${var}")
  ENDFOREACH()
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
  MESSAGE(AUTHOR_WARNING ${WARNING_MESSAGE})
  MESSAGE("================================================================================")
ENDIF()

SET(DART_TESTING_TIMEOUT 2400 CACHE INTERNAL "Maximum time allowed before CTest will kill the test.")
IF(UNIX)
  SET(MEMORYCHECK_COMMAND "/usr/bin/valgrind --show-reachable=no")
ENDIF()

IF(NOT INSTALL_PREFIX)
  SET(CMAKE_INSTALL_PREFIX "/usr")
ELSE()
  IF(WIN32)
    STRING(REPLACE "\\" "/" INSTALL_PREFIX ${INSTALL_PREFIX})
  ENDIF()
  SET(CMAKE_INSTALL_PREFIX "${INSTALL_PREFIX}")
ENDIF()

###################################################################################################
MESSAGE("")
MESSAGE("Package version is set to \"${pddate}\"")
MESSAGE("================================================================================")
MESSAGE("")
MESSAGE("Tests included: \"${MAIDSAFE_TEST_TYPE}\"")
MESSAGE("")
MESSAGE("    To include all tests,                     ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=_")
MESSAGE("    To include behavioural tests,           ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=BEH")
MESSAGE("    To include functional tests,           ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=FUNC")
MESSAGE("================================================================================")
MESSAGE("")
MESSAGE("Install prefix is set to ${CMAKE_INSTALL_PREFIX}")
MESSAGE("")
MESSAGE("    To alter this (e.g. to /usr/local),  ${ERROR_MESSAGE_CMAKE_PATH} -DINSTALL_PREFIX=/usr/local")
MESSAGE("================================================================================")
MESSAGE("")

SET(MAIDSAFE_BASE_INSTALL_FILES
      base/alternativestore.h
      base/crypto.h
      base/log.h
      base/online.h
      base/routingtable.h
      base/utils.h
      base/validationinterface.h)
SET(MAIDSAFE_KAD_INSTALL_FILES
      kademlia/contact.h
      kademlia/kadid.h
      kademlia/knode-api.h)
SET(MAIDSAFE_MAIN_INSTALL_FILES
      maidsafe/maidsafe-dht.h
      maidsafe/maidsafe-dht_config.h)
SET(MAIDSAFE_PROTO_INSTALL_FILES
      protobuf/contact_info.pb.h
      protobuf/general_messages.pb.h
      protobuf/kademlia_service_messages.pb.h
      protobuf/signed_kadvalue.pb.h)
SET(MAIDSAFE_RPC_INSTALL_FILES
      rpcprotocol/channel-api.h
      rpcprotocol/channelmanager-api.h)
SET(MAIDSAFE_TRANS_INSTALL_FILES
      transport/transport-api.h
      transport/transporthandler-api.h
      transport/transportudt.h)
# Check the script /build/Win_MSVC/extract_includes.bat matches this list
FILE(STRINGS ${${PROJECT_NAME}_ROOT}/build/Win_MSVC/extract_includes.bat EXTRACT_INCLUDE_BAT)
STRING(REPLACE "\\" "/" EXTRACT_INCLUDE_BAT "${EXTRACT_INCLUDE_BAT}")
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_BASE_INSTALL_FILES})
  STRING(REGEX MATCH ${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_BASE_INSTALL_FILES ${ABS_MAIDSAFE_BASE_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_KAD_INSTALL_FILES})
  STRING(REGEX MATCH ${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_KAD_INSTALL_FILES ${ABS_MAIDSAFE_KAD_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_MAIN_INSTALL_FILES})
  STRING(REGEX MATCH ${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_MAIN_INSTALL_FILES ${ABS_MAIDSAFE_MAIN_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_PROTO_INSTALL_FILES})
  STRING(REGEX MATCH ${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_PROTO_INSTALL_FILES ${ABS_MAIDSAFE_PROTO_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_RPC_INSTALL_FILES})
  STRING(REGEX MATCH ${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_RPC_INSTALL_FILES ${ABS_MAIDSAFE_RPC_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_TRANS_INSTALL_FILES})
  STRING(REGEX MATCH ${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_TRANS_INSTALL_FILES ${ABS_MAIDSAFE_TRANS_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()

IF(MSVC)
  INSTALL(TARGETS maidsafe_dht_static # maidsafe_dht
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION bin
            ARCHIVE DESTINATION lib
          )
ELSE()
  INSTALL(TARGETS maidsafe_dht_static # maidsafe_dht
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
          )
ENDIF()

INSTALL(FILES ${ABS_MAIDSAFE_BASE_INSTALL_FILES} DESTINATION include/maidsafe/base)
INSTALL(FILES ${ABS_MAIDSAFE_KAD_INSTALL_FILES} DESTINATION include/maidsafe/kademlia)
INSTALL(FILES ${ABS_MAIDSAFE_MAIN_INSTALL_FILES} DESTINATION include/maidsafe)
INSTALL(FILES ${ABS_MAIDSAFE_PROTO_INSTALL_FILES} DESTINATION include/maidsafe/protobuf)
INSTALL(FILES ${ABS_MAIDSAFE_RPC_INSTALL_FILES} DESTINATION include/maidsafe/rpcprotocol)
INSTALL(FILES ${ABS_MAIDSAFE_TRANS_INSTALL_FILES} DESTINATION include/maidsafe/transport)

IF(CMAKE_BUILD_TYPE MATCHES Release)
  SET(CPACK_PACKAGE_VERSION_PATCH ${pddate})
  SET(CPACK_PACKAGE_VERSION "0.1.${pddate}")
  SET(CPACK_PACKAGE_VERSION_MAJOR "0")
  SET(CPACK_PACKAGE_VERSION_MINOR "1")
  SET(CPACK_PACKAGE_NAME "maidsafe_dht")
  SET(CPACK_PACKAGE_CONTACT "info@maidsafe.net")
  SET(CPACK_PACKAGE_VENDOR "maidsafe.net")
  SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Perpetual Data - Client and Vault applications")
  SET(CPACK_PACKAGE_INSTALL_DIRECTORY "maidsafe")
  SET(CPACK_PACKAGE_DESCRIPTION_FILE "${${PROJECT_NAME}_SOURCE_DIR}/../docs/description.txt")
  SET(CPACK_RESOURCE_FILE_LICENSE "${${PROJECT_NAME}_SOURCE_DIR}/../docs/LICENSE.txt")
  SET(CPACK_RESOURCE_FILE_README "${${PROJECT_NAME}_SOURCE_DIR}/../docs/readme.txt")
  SET(CPACK_RESOURCE_FILE_WELCOME "${${PROJECT_NAME}_SOURCE_DIR}/../docs/welcome.txt")

  MESSAGE("Install directory is set to \"${CPACK_PACKAGE_INSTALL_DIRECTORY}\"")
  MESSAGE("================================================================================")

  IF(UNIX)
    SET(CPACK_SET_DESTDIR on)
    SET(CPACK_GENERATOR DEB;RPM;TGZ)
  ELSE()
    SET(CPACK_GENERATOR ZIP)
  ENDIF()
  INCLUDE(CPack)
ELSE()
  FILE(REMOVE ${${PROJECT_NAME}_BINARY_DIR}/CPackConfig.cmake ${${PROJECT_NAME}_BINARY_DIR}/CPackSourceConfig.cmake)
ENDIF()
