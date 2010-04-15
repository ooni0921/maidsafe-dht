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
PROJECT(maidsafe_dht)
MESSAGE("================================================================================\n")
SET(CMAKE_CACHEFILE "${CMAKE_CACHEFILE_DIR}/CMakeCache.txt")
IF(WIN32)
  STRING(REPLACE "/" "\\" CMAKE_CACHEFILE ${CMAKE_CACHEFILE})
ENDIF()
SET(ERROR_MESSAGE "No generator previously specified.  Run:\n")
IF(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\trm ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\tcmake ../.. -G\"CodeBlocks - Unix Makefiles\"\n\n")
ELSE()
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\tcmake ../.. -G\"CodeBlocks - MinGW Makefiles\"\n\n")
ENDIF()
SET(ERROR_MESSAGE "${ERROR_MESSAGE}To see a full list of generators, run:\n\tcmake ../.. --help\n")
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE "Release" CACHE INTERNAL "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF()

IF(NOT MAIDSAFE_TEST_TYPE)
  SET(MAIDSAFE_TEST_TYPE "BEH" CACHE INTERNAL "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
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
UNSET(LIBRARY_OUTPUT_PATH CACHE)
UNSET(EXECUTABLE_OUTPUT_PATH CACHE)
IF(MSVC)
  IF(CMAKE_CL_64)
    SET(LIBRARY_OUTPUT_PATH ${maidsafe_dht_BINARY_DIR}/bin/x64 CACHE PATH "Library target dir (x64).")
    SET(EXECUTABLE_OUTPUT_PATH ${maidsafe_dht_BINARY_DIR}/bin/x64 CACHE PATH "Executable target dir (x64).")
  ELSE()
    SET(LIBRARY_OUTPUT_PATH ${maidsafe_dht_BINARY_DIR}/bin/win32 CACHE PATH "Library target dir (win32).")
    SET(EXECUTABLE_OUTPUT_PATH ${maidsafe_dht_BINARY_DIR}/bin/win32 CACHE PATH "Executable target dir (win32).")
  ENDIF()
ELSE()
  SET(EXECUTABLE_OUTPUT_PATH ${maidsafe_dht_BINARY_DIR}/bin CACHE PATH "Executable target dir.")
  SET(LIBRARY_OUTPUT_PATH ${maidsafe_dht_BINARY_DIR}/bin CACHE PATH "Executable target dir.")
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
  SET(DEFAULT_LIBRARY_DIR ${DEFAULT_LIBRARY_DIR} ${ADD_LIBRARY_DIR} CACHE INTERNAL "Path to libraries directories" FORCE)
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
INCLUDE(${maidsafe_dht_SOURCE_DIR}/build/maidsafe_FindBoost.cmake)
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
    MESSAGE("If installed run cmake ../.. -DGLOG_ROOT=<The root directory of glog install prefix>")
    MESSAGE(" You can download it at http://code.google.com/p/google-glog\n")
  ENDIF()
ENDIF()

CONFIGURE_FILE(${maidsafe_dht_SOURCE_DIR}/config.h.in ${maidsafe_dht_SOURCE_DIR}/maidsafe/config.h)

###################################################################################################
# Google Test library search                                                                      #
###################################################################################################
INCLUDE(${maidsafe_dht_SOURCE_DIR}/build/maidsafe_FindGtest.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gtest_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Gtest_LIBRARY_DIR} ${Gtest_LIBRARY_DIR_DEBUG})


#  IF(APPLE)
#    FOREACH(LIB ${Gtest_LIBRARIES})
#      GET_FILENAME_COMPONENT(LIB_PATH ${LIB} PATH)
#      SET(LIBS_DIRS ${LIBS_DIRS} ${LIB_PATH})
#    ENDFOREACH()
#    SET(Gtest_LIBRARIES "gtest")
#  ENDIF()


###################################################################################################
# Protocol Buffers library search                                                                 #
###################################################################################################
FILE(GLOB PROTO_FILES RELATIVE ${maidsafe_dht_SOURCE_DIR} "protobuf/*.proto")
FILE(GLOB TEST_PROTO_FILES RELATIVE ${maidsafe_dht_SOURCE_DIR} "tests/rpcprotocol/*.proto")
SET(PROTO_FILES ${PROTO_FILES} ${TEST_PROTO_FILES})
INCLUDE(${maidsafe_dht_SOURCE_DIR}/build/maidsafe_FindProtobuf.cmake)
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
  FOREACH(library ${SYS_LIB})
    FIND_LIBRARY(CURRENT_LIB ${library})
    IF(CURRENT_LIB)
      MESSAGE("-- Found library ${CURRENT_LIB}")
    ELSE()
      MESSAGE(FATAL_ERROR "\nCouldn't find library ${library}")
    ENDIF()
    UNSET(CURRENT_LIB CACHE)
  ENDFOREACH()
ELSEIF(WIN32)
  IF(MSVC)
    SET(SYS_LIB ws2_32.lib odbc32.lib odbccp32.lib WSock32.lib IPHlpApi.lib)
  ELSE()
    SET(SYS_LIB advapi32 kernel32 ws2_32 iphlpapi mswsock)
  ENDIF()
  FOREACH(library ${SYS_LIB})
    FIND_LIBRARY(CURRENT_LIB ${library})
    IF(CURRENT_LIB)
      MESSAGE("-- Found library ${CURRENT_LIB}")
      GET_FILENAME_COMPONENT(CURRENT_LIBRARY_DIR ${CURRENT_LIB} PATH)
      SET(LIBS_DIRS ${LIBS_DIRS} ${CURRENT_LIBRARY_DIR})
    ELSE()
      SET(ERROR_MESSAGE "\nCould not find library ${library}.  Run\n")
      SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DADD_LIBRARY_DIR=<Path to ${library} directory>")
      MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
    ENDIF()
    UNSET(CURRENT_LIB CACHE)
  ENDFOREACH()
ENDIF()

IF(MSVC)
  SET(SYS_LIB ${SYS_LIB} ${GLOG_LIB})
ELSE()
  SET(SYS_LIB ${SYS_LIB} ${GLOG_LIB} ${Protobuf_LIBRARY})
ENDIF()

SET(LIBS_DIRS ${LIBS_DIRS} ${LIBRARY_OUTPUT_PATH})
LIST(REMOVE_DUPLICATES LIBS_DIRS)
IF(MSVC)
  LINK_DIRECTORIES(${LIBS_DIRS})
ENDIF()

INCLUDE_DIRECTORIES(${maidsafe_dht_SOURCE_DIR})
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
       libupnp/igd_desc_parse.c
       libupnp/minixml.c
       libupnp/minisoap.c
       libupnp/miniwget.c
       libupnp/upnpcommands.c
       libupnp/upnpreplyparse.c
       libupnp/upnperrors.c
       libupnp/miniupnpc.c
       libupnp/minissdpc.c)
FILE(GLOB M_NATPMP_C "nat-pmp/*.c*")
FILE(GLOB M_NATPMP_H "nat-pmp/*.h*")
LIST(APPEND M_NATPMP_DIR ${M_NATPMP_C} ${M_NATPMP_H})
FILE(GLOB M_UPNP_C "upnp/*.c*")
FILE(GLOB M_UPNP_H "upnp/*.h*")
LIST(APPEND M_UPNP_DIR ${M_UPNP_C} ${M_UPNP_H})
LIST(REMOVE_ITEM M_UPNP_DIR "${maidsafe_dht_SOURCE_DIR}/upnp/upnpclientimpl.cc")
LIST(REMOVE_ITEM M_UPNP_DIR "${maidsafe_dht_SOURCE_DIR}/upnp/upnpclientimpl.h")
FILE(GLOB M_PROTOBUF_C "protobuf/*.c*")
FILE(GLOB M_PROTOBUF_H "protobuf/*.h*")
LIST(APPEND M_PROTOBUF_DIR ${M_PROTOBUF_C} ${M_PROTOBUF_H})
FILE(GLOB M_BASE_C "base/*.c*")
FILE(GLOB M_BASE_H "base/*.h*")
LIST(APPEND M_BASE_DIR ${M_BASE_C} ${M_BASE_H})
FILE(GLOB M_KADEMLIA_C "kademlia/*.c*")
FILE(GLOB M_KADEMLIA_H "kademlia/*.h*")
LIST(APPEND M_KADEMLIA_DIR ${M_KADEMLIA_C} ${M_KADEMLIA_H})
LIST(APPEND STYLE_KADEMLIA ${M_KADEMLIA_C} ${M_KADEMLIA_H})
FILE(GLOB PB_KADEMLIA "kademlia/*.pb.*")
FILE(GLOB M_TRANSPORT_C "transport/*.c*")
FILE(GLOB M_TRANSPORT_H "transport/*.h*")
LIST(APPEND M_TRANSPORT_DIR ${M_TRANSPORT_C} ${M_TRANSPORT_H})
FILE(GLOB MAIDSAFE_C "maidsafe/*.c*")
FILE(GLOB MAIDSAFE_H "maidsafe/*.h*")
LIST(APPEND MAIDSAFE_DIR ${MAIDSAFE_C} ${MAIDSAFE_H})
####    TESTS    ####
FILE(GLOB T_BASE_C "tests/base/*.c*")
FILE(GLOB T_BASE_H "tests/base/*.h*")
LIST(APPEND T_BASE_DIR ${T_BASE_C} ${T_BASE_H})
FILE(GLOB T_KADEMLIA_C "tests/kademlia/*.c*")
FILE(GLOB T_KADEMLIA_H "tests/kademlia/*.h*")
LIST(APPEND T_KADEMLIA_DIR ${T_KADEMLIA_C} ${T_KADEMLIA_H})
LIST(REMOVE_ITEM T_KADEMLIA_DIR "${maidsafe_dht_SOURCE_DIR}/tests/kademlia/testknode.cc")
FILE(GLOB T_TRANSPORT_C "tests/transport/*.c*")
FILE(GLOB T_TRANSPORT_H "tests/transport/*.h*")
LIST(APPEND T_TRANSPORT_DIR ${T_TRANSPORT_C} ${T_TRANSPORT_H})
FILE(GLOB T_MAIN  "tests/main.cc" "tests/validationimpl.h")
FILE(GLOB M_RPCPROTO_C "rpcprotocol/*.c*")
FILE(GLOB M_RPCPROTO_H "rpcprotocol/*.h*")
LIST(APPEND M_RPCPROTO_DIR ${M_RPCPROTO_C} ${M_RPCPROTO_H})
LIST(APPEND STYLE_RPCPROTO ${M_RPCPROTO_C} ${M_RPCPROTO_H})
FILE(GLOB T_RPCPROTO_C "tests/rpcprotocol/*.c*")
FILE(GLOB T_RPCPROTO_H "tests/rpcprotocol/*.h*")
LIST(APPEND T_RPCPROTO_DIR ${T_RPCPROTO_C} ${T_RPCPROTO_H})
FILE(GLOB STYLE_RPCPROTO_C "tests/rpcprotocol/*.c*")
FILE(GLOB STYLE_RPCPROTO_H "tests/rpcprotocol/*.h*")
LIST(APPEND STYLE_RPCPROTO_DIR ${STYLE_RPCPROTO_C} ${STYLE_RPCPROTO_H})
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${maidsafe_dht_SOURCE_DIR}/tests/rpcprotocol/testservices.pb.h")
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${maidsafe_dht_SOURCE_DIR}/tests/rpcprotocol/testservices.pb.cc")
FILE(GLOB T_NATPMP_C "tests/nat-pmp/*.c*")
FILE(GLOB T_NATPMP_H "tests/nat-pmp/*.h*")
LIST(APPEND T_NATPMP_DIR ${T_NATPMP_C} ${T_NATPMP_H})
FILE(GLOB T_UPNP_C "tests/upnp/*.c*")
FILE(GLOB T_UPNP_H "tests/upnp/*.h*")
LIST(APPEND T_UPNP_DIR ${T_UPNP_C} ${T_UPNP_H})
FILE(GLOB T_FUNC_KADEMLIA_C "tests/functionalkademlia/*.c*")
FILE(GLOB T_FUNC_KADEMLIA_H "tests/functionalkademlia/*.h*")
LIST(APPEND T_FUNC_KADEMLIA_DIR ${T_FUNC_KADEMLIA_C} ${T_FUNC_KADEMLIA_H})
LIST(REMOVE_ITEM T_FUNC_KADEMLIA_DIR "tests/kademlia/testknode.cc")
FILE(GLOB T_DEMO_C "tests/demo/*.c*")
FILE(GLOB T_DEMO_H "tests/demo/*.h*")
LIST(APPEND T_DEMO_DIR ${T_DEMO_C} ${T_DEMO_H})
LIST(APPEND DHT_SOURCE_FILES ${M_BASE_DIR} ${M_KADEMLIA_DIR} ${M_TRANSPORT_DIR} ${M_PROTOBUF_DIR} ${M_RPCPROTO_DIR} ${M_LIBUPNP_DIR} ${M_UPNP_DIR} ${M_NATPMP_DIR} ${MAIDSAFE_DIR})
###################################################################################################
# Traverse subdirs for imported 3rd party libs                                                    #
###################################################################################################
ADD_SUBDIRECTORY(udt)
ADD_SUBDIRECTORY(cryptopp)

###################################################################################################
# All Platforms:  Add Test Exes and Create all maidsafe_dht libs                                  #
###################################################################################################
ADD_EXECUTABLE(TESTbase ${T_MAIN} ${T_BASE_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTkademlia ${T_MAIN} ${T_KADEMLIA_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTknode "tests/kademlia/testknode.cc" ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTtransport ${T_MAIN} ${T_TRANSPORT_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTrpcprotocol ${T_MAIN} ${T_RPCPROTO_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTnatpmp ${T_MAIN} ${T_NATPMP_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTupnp ${T_MAIN} ${T_UPNP_DIR} ${MAIDSAFE_H})
# Need to use __declspec(dllimport) in all API header files before linking to SHARED library target
#ADD_EXECUTABLE(kaddemo ${T_DEMO_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(kaddemo_static ${T_DEMO_DIR} ${MAIDSAFE_H})

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
  TARGET_LINK_LIBRARIES(TESTbase maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARIES} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTtransport maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARIES} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARIES} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARIES} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTknode maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARIES} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARIES} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTupnp maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARIES} ${SYS_LIB})
#  IF(WIN32)
#    TARGET_LINK_LIBRARIES(maidsafe_dht "-Wl,--enable-auto-import" udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(kaddemo "-Wl,--enable-auto-import" maidsafe_dht udt cryptopp)
#  ELSEIF(APPLE)
#    TARGET_LINK_LIBRARIES(maidsafe_dht udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht udt cryptopp ${SYS_LIB})
#  ELSE()
#    TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht udt cryptopp ${SYS_LIB})
#  ENDIF()
  TARGET_LINK_LIBRARIES(kaddemo_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
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
  
  # CMake defaults stack size to 10MB.  Set this to windows default of 1MB
  STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
  STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")

  # defining UDT_STATIC prevents declaring __declspec for UDT API functions
  SET_TARGET_PROPERTIES(maidsafe_dht_static TESTbase TESTkademlia TESTknode TESTnatpmp TESTrpcprotocol TESTtransport TESTupnp kaddemo_static PROPERTIES
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

#  TARGET_LINK_LIBRARIES(maidsafe_dht udt_static cryptopp_static iphlpapi.lib)
#  TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})

  FOREACH (DLIB ${DEBUG_LIBS})
    TARGET_LINK_LIBRARIES(TESTbase debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTkademlia debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTknode debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTnatpmp debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTrpcprotocol debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTtransport debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTupnp debug ${DLIB})
    TARGET_LINK_LIBRARIES(kaddemo_static debug ${DLIB})
#    TARGET_LINK_LIBRARIES(maidsafe_dht debug ${DLIB})
#    TARGET_LINK_LIBRARIES(kaddemo debug ${DLIB})
  ENDFOREACH()
  FOREACH (DLIB ${Gtest_LIBRARIES_DEBUG})
    TARGET_LINK_LIBRARIES(TESTbase debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTkademlia debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTknode debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTnatpmp debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTrpcprotocol debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTtransport debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTupnp debug ${DLIB})
  ENDFOREACH()

  FOREACH(RLIB ${RELEASE_LIBS})
    TARGET_LINK_LIBRARIES(TESTbase optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTkademlia optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTknode optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTnatpmp optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTrpcprotocol optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTtransport optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTupnp optimized ${RLIB})
    TARGET_LINK_LIBRARIES(kaddemo_static optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(maidsafe_dht optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(kaddemo optimized ${RLIB})
  ENDFOREACH()
  FOREACH(RLIB ${Gtest_LIBRARIES})
    TARGET_LINK_LIBRARIES(TESTbase optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTkademlia optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTknode optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTnatpmp optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTrpcprotocol optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTtransport optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTupnp optimized ${RLIB})
  ENDFOREACH()
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

  SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp kaddemo_static  PROPERTIES LINK_FLAGS "-mthreads " )
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
  SET_TARGET_PROPERTIES(TESTkademlia TESTknode PROPERTIES COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(base/crypto.cc  PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES(base/utils.cc  PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES("*boost/*" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES("*google/protobuf/repeated_field.h" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES(${M_PROTOBUF_DIR}  PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
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
    ADD_TEST(STYLE_CHECK_KAD ${maidsafe_dht_SOURCE_DIR}/cpplint.py ${STYLE_KADEMLIA} ${T_KADEMLIA_DIR} ${T_FUNC_KADEMLIA_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_KAD PROPERTY LABELS Functional Kademlia CodingStyle)
    ADD_TEST(STYLE_CHECK_BASE ${maidsafe_dht_SOURCE_DIR}/cpplint.py ${M_BASE_DIR} ${T_BASE_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_BASE PROPERTY LABELS Functional Base CodingStyle)
    ADD_TEST(STYLE_CHECK_RPC ${maidsafe_dht_SOURCE_DIR}/cpplint.py ${M_RPCPROTO_DIR} ${STYLE_RPCPROTO_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_RPC PROPERTY LABELS Functional RpcProtocol CodingStyle)
  ELSE()
    ADD_TEST(STYLE_CHECK finderrorsall.bat)
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
  IF(NOT EXISTS ${EXECUTABLE_OUTPUT_PATH}/${TEST_EXECUTABLE})
    IF(FOUNDALLTESTS)
      SET(FOUNDALLTESTS false)
      MESSAGE("")
      MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
      MESSAGE("")
    ENDIF()
    MESSAGE(WARNING "Cannot find ${EXECUTABLE_OUTPUT_PATH}/${TEST_EXECUTABLE}")
  ELSE()
    EXECUTE_PROCESS(COMMAND ${EXECUTABLE_OUTPUT_PATH}/${TEST_EXECUTABLE} --gtest_list_tests OUTPUT_VARIABLE maid_tests)
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
            ADD_TEST(${tst} ${EXECUTABLE_OUTPUT_PATH}/${TEST_EXECUTABLE} --gtest_filter=*${tst}*)
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
            EXECUTE_PROCESS(COMMAND ${EXECUTABLE_OUTPUT_PATH}/${TEST_EXECUTABLE} --gtest_list_tests --gtest_filter=*${tst}* OUTPUT_VARIABLE repeateds)
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
MESSAGE("    To include all tests,                     cmake ../.. -DMAIDSAFE_TEST_TYPE=_")
MESSAGE("    To include behavioural tests,           cmake ../.. -DMAIDSAFE_TEST_TYPE=BEH")
MESSAGE("    To include functional tests,           cmake ../.. -DMAIDSAFE_TEST_TYPE=FUNC")
MESSAGE("================================================================================")
MESSAGE("")
MESSAGE("Build type is set to \"${CMAKE_BUILD_TYPE}\"")
MESSAGE("")
MESSAGE("    To alter this (e.g. to Debug),          cmake ../.. -DCMAKE_BUILD_TYPE=Debug")
MESSAGE("    Options are Release, Debug, RelWithDebInfo, MinSizeRel")
MESSAGE("================================================================================")
MESSAGE("")
MESSAGE("Install prefix is set to ${CMAKE_INSTALL_PREFIX}")
MESSAGE("")
MESSAGE("    To alter this (e.g. to /usr/local),  cmake ../.. -DINSTALL_PREFIX=/usr/local")
MESSAGE("================================================================================")
MESSAGE("")

SET(PROTOBUF_INSTALL_FILES protobuf/signed_kadvalue.pb.h protobuf/kademlia_service_messages.pb.h protobuf/contact_info.pb.h protobuf/general_messages.pb.h)

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

INSTALL(FILES ${MAIDSAFE_H} ${PROTOBUF_INSTALL_FILES} DESTINATION include/maidsafe)

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
  SET(CPACK_PACKAGE_DESCRIPTION_FILE "${maidsafe_dht_SOURCE_DIR}/../docs/description.txt")
  SET(CPACK_RESOURCE_FILE_LICENSE "${maidsafe_dht_SOURCE_DIR}/../docs/LICENSE.txt")
  SET(CPACK_RESOURCE_FILE_README "${maidsafe_dht_SOURCE_DIR}/../docs/readme.txt")
  SET(CPACK_RESOURCE_FILE_WELCOME "${maidsafe_dht_SOURCE_DIR}/../docs/welcome.txt")

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
  FILE(REMOVE ${maidsafe_dht_BINARY_DIR}/CPackConfig.cmake ${maidsafe_dht_BINARY_DIR}/CPackSourceConfig.cmake)
ENDIF()
