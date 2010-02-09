CMAKE_MINIMUM_REQUIRED(VERSION 2.8 FATAL_ERROR)
PROJECT(MAIDSAFE)
MESSAGE("================================================================================\n")
SET(CMAKE_CACHEFILE "${CMAKE_CACHEFILE_DIR}/CMakeCache.txt")
IF(WIN32)
  STRING(REPLACE "/" "\\" CMAKE_CACHEFILE ${CMAKE_CACHEFILE})
ENDIF()
SET(ERROR_MESSAGE "No generator previously specified.  Run:\n")
IF(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\trm ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\tcmake ../.. -G\"CodeBlocks - Unix Makefiles\"\n\n")
ELSE(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\tcmake ../.. -G\"CodeBlocks - MinGW Makefiles\"\n\n")
ENDIF(UNIX)
SET(ERROR_MESSAGE "${ERROR_MESSAGE}To see a full list of generators, run:\n\tcmake ../.. --help\n")
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE "Release" CACHE INTERNAL "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)
IF(NOT MAIDSAFE_TEST_TYPE)
  SET(MAIDSAFE_TEST_TYPE "BEH" CACHE INTERNAL "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
ENDIF(NOT MAIDSAFE_TEST_TYPE)

IF(UNIX)
  EXECUTE_PROCESS(COMMAND date +%a%d%m%y OUTPUT_VARIABLE pddate OUTPUT_STRIP_TRAILING_WHITESPACE)
ELSE(UNIX)
  EXECUTE_PROCESS(COMMAND CMD /C DATE /T OUTPUT_VARIABLE pddate OUTPUT_STRIP_TRAILING_WHITESPACE)
  STRING(REPLACE "/" "" pddate ${pddate})
  STRING(SUBSTRING ${pddate} 0 4 pddateddmm)
  STRING(SUBSTRING ${pddate} 6 2 pddateyy)
  SET(pddate ${pddateddmm}${pddateyy})
ENDIF(UNIX)

###################################################################################################
# Set default include and library directories                                                     #
###################################################################################################
IF(WIN32)
  IF(MSVC)
    SET(INCLUDE_DIR c:/msvc/include c:/include )
    SET(LIB_DIR c:/msvc/lib c:/lib )
  ENDIF(MSVC)
    SET(INCLUDE_DIR c:/usr/include)
    SET(LIB_DIR c:/usr/lib)
    SET(DOC_LIB_DIR " - e.g. \"c:\\usr\\lib\"")
    LINK_DIRECTORIES(c:/MinGW/lib/ c:/MinGW/mingw32/lib/ c:/usr/lib/)
ELSE(WIN32)
  SET(INCLUDE_DIR /usr/include /usr/local/include /opt/local/var/macports/software/macfuse/1.7_0/opt/local/include)
  IF(CMAKE_CL_64)
    SET(LIB_DIR /usr/lib /usr/local/lib /usr/lib64 /usr/local/lib64)
  ELSE(CMAKE_CL_64)
    SET(LIB_DIR /usr/lib /usr/local/lib)
  ENDIF(CMAKE_CL_64)
  IF(APPLE)
    SET(CMAKE_OSX_SYSROOT "/")
  ENDIF(APPLE)
ENDIF(WIN32)
SET(CMAKE_REQUIRED_INCLUDES ${INCLUDE_DIR})

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
IF (MSVC)
  IF (CMAKE_CL_64)
    SET (LIBRARY_OUTPUT_PATH ${MAIDSAFE_BINARY_DIR}/bin/x64 CACHE PATH "Library target dir (x64).")
    SET (EXECUTABLE_OUTPUT_PATH ${MAIDSAFE_BINARY_DIR}/bin/x64 CACHE PATH "Executable target dir (x64).")
  ELSE (CMAKE_CL_64)
    SET (LIBRARY_OUTPUT_PATH ${MAIDSAFE_BINARY_DIR}/bin/win32 CACHE PATH "Library target dir (win32).")
    SET (EXECUTABLE_OUTPUT_PATH ${MAIDSAFE_BINARY_DIR}/bin/win32 CACHE PATH "Executable target dir (win32).")
  ENDIF (CMAKE_CL_64)
ELSE(MSVC)
	SET (EXECUTABLE_OUTPUT_PATH ${MAIDSAFE_BINARY_DIR}/bin CACHE PATH "Executable target dir .")
	SET (LIBRARY_OUTPUT_PATH ${MAIDSAFE_BINARY_DIR}/bin CACHE PATH "Executable target dir .")
ENDIF (MSVC)

#message(FATAL_ERROR "maidsafe bin dir" ${MAIDSAFE_BINARY_DIR})
###################################################################################################
# Boost libraries search                                                                          #
###################################################################################################
MESSAGE(STATUS "Check for boost libraries")
SET(Boost_USE_MULTITHREAD ON)
SET(Boost_ADDITIONAL_VERSIONS "1.41.0")
SET(Boost_FIND_REQUIRED "1.41.0")
SET(Boost_USE_STATIC_LIBS ON)
SET(BOOST_LIB_DIAGNOSTIC OFF)
#ADD_DEFINITIONS(-DBOOST_ALL_DYN_LINK)
IF (MSVC)
        SET (BOOST_ROOT "${BOOST_INC_DIR}")
        IF (CMAKE_CL_64)
                SET (BOOST_LIBRARYDIR "${BOOST_LIB_DIR}")
        ENDIF (CMAKE_CL_64)
ELSE (MSVC)
        SET (BOOST_ROOT "c:/usr")
	#        SET (BOOST_INCLUDEDIR "/opt/boost_1_41_0")
	#SET (BOOST_ROOT "/opt/boost_1_41_0")
        SET (OpenSSL_INCLUDE_DIR "/usr/include")
ENDIF (MSVC)

FIND_PACKAGE (Boost COMPONENTS date_time filesystem thread program_options system regex)
IF (NOT Boost_VERSION)
        MESSAGE (FATAL "No proper boost version found. Halting.")
ELSE (NOT Boost_VERSION)
        MESSAGE (STATUS "Found Boost " ${Boost_LIB_VERSION})
ENDIF (NOT Boost_VERSION)

###################################################################################################
# Google Glog library (logging) search. Only on UNIX, since currently it cannot be compiled on    #
# Windows with MinGW                                                                              #
###################################################################################################
INCLUDE(CheckIncludeFileCXX)
IF(UNIX)
  UNSET(GLOG_LIB CACHE)
  UNSET(GLOG_INCLUDE CACHE)
  FIND_LIBRARY(GLOG_LIB NAMES libglog.a glog DOC "Path to glog library${DOC_LIB_DIR}")
  CHECK_INCLUDE_FILE_CXX(glog/logging.h GLOG_INCLUDE)
  IF(GLOG_LIB AND GLOG_INCLUDE)
    SET(HAVE_GLOG GLOG_LIB)
    MESSAGE("Using GLOG")
  ELSE(GLOG_LIB AND GLOG_INCLUDE)
    SET(GLOG_LIB "")
    MESSAGE("Not using GLOG")
  ENDIF(GLOG_LIB AND GLOG_INCLUDE)
ENDIF(UNIX)

CONFIGURE_FILE(${MAIDSAFE_SOURCE_DIR}/config.h.in ${MAIDSAFE_SOURCE_DIR}/maidsafe/config.h)

###################################################################################################
# Google Test library search                                                                      #
###################################################################################################
UNSET(GTEST_LIBRARY CACHE)
UNSET(GTEST_MAIN_LIBRARY CACHE)
UNSET(GTEST_INCLUDE_DIR CACHE)
UNSET(GTEST_INCLUDE CACHE)
IF(GTEST_ROOT_PATH)
  SET(GTEST_ROOT_PATH ${GTEST_ROOT_PATH} CACHE INTERNAL "Path to Google Test library directory" FORCE)
  SET(ENV{GTEST_ROOT} ${GTEST_ROOT_PATH})
ELSE()
  SET(ENV{GTEST_ROOT} ${LIB_DIR})
ENDIF()
IF(GTEST_INCLUDE_PATH)
  SET(GTEST_INCLUDE_PATH ${GTEST_INCLUDE_PATH} CACHE INTERNAL "Path to Google Test include directory" FORCE)
  SET(GTEST_INCLUDE_DIR ${GTEST_INCLUDE_PATH} CACHE INTERNAL "Path to Google Test include directory" FORCE)
ELSE()
  FOREACH(INC_OPTION ${INCLUDE_DIR})
    SET(GTEST_INCLUDE_DIR ${GTEST_INCLUDE_DIR} ${INC_OPTION}/gtest CACHE INTERNAL "Path to Google Test include directory" FORCE)
  ENDFOREACH()
ENDIF()
INCLUDE(FindGTest)
FIND_PACKAGE(GTest)
CHECK_INCLUDE_FILE_CXX(gtest/gtest.h GTEST_INCLUDE)
IF(GTEST_LIBRARY)
  IF(NOT GTEST_INCLUDE)
    SET(ERROR_MESSAGE "\nCould not find Google Test.  NO GTEST.H - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/googletest\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Test is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DGTEST_INCLUDE_PATH=<Path to gtest include directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
ELSE(GTEST_LIBRARY)
  SET(ERROR_MESSAGE "\nCould not find Google Test.  NO GTEST LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/googletest\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Test is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DGTEST_ROOT_PATH=<Path to gtest library directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF(GTEST_LIBRARY)

###################################################################################################
# Protocol Buffers library search                                                                 #
###################################################################################################
FUNCTION(GENERATE_PROTO_FILES PROTO_FILE CACHE_NAME)
  FILE(STRINGS ${PROTO_FILE} PROTO_STRING)
  UNSET(NEW_${ARGV1} CACHE)
  SET(NEW_${ARGV1} ${PROTO_STRING} CACHE STRING "Google Protocol Buffers - new file contents for ${ARGV1}")
  IF((${FORCE_PROTOC_COMPILE}) OR (NOT "${NEW_${ARGV1}}" STREQUAL "${${ARGV1}}"))
    GET_FILENAME_COMPONENT(PROTO_FILE_ROOT ${PROTO_FILE} PATH)
    GET_FILENAME_COMPONENT(PROTO_FILE_NAME ${PROTO_FILE} NAME)
    EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --proto_path=${MAIDSAFE_SOURCE_DIR}/${PROTO_FILE_ROOT} --cpp_out=${MAIDSAFE_SOURCE_DIR}/${PROTO_FILE_ROOT} ${MAIDSAFE_SOURCE_DIR}/${PROTO_FILE} RESULT_VARIABLE PROTO_RES ERROR_VARIABLE PROTO_ERR)
    UNSET(${ARGV1} CACHE)
    IF(NOT ${PROTO_RES})
      MESSAGE("--   Generated files from ${PROTO_FILE_NAME}")
      SET(${ARGV1} ${PROTO_STRING} CACHE STRING "Google Protocol Buffers - file contents for ${PROTO_FILE}")
    ELSE()
      MESSAGE(FATAL_ERROR "Failed trying to generate files from ${PROTO_FILE}\n${PROTO_ERR}")
    ENDIF()
  ENDIF()
  UNSET(NEW_${ARGV1} CACHE)
ENDFUNCTION()

UNSET(PROTOBUF_PROTOC_EXECUTABLE CACHE)
UNSET(PROTOBUF_INCLUDE CACHE)
UNSET(Protobuf_LIBRARY_RELEASE CACHE)
UNSET(Protobuf_LIBRARY_DEBUG CACHE)
UNSET(PROTOBUF_LIBRARY CACHE)

INCLUDE(CheckLibraryExists)
IF(MSVC)
  FIND_PROGRAM(PROTOBUF_PROTOC_EXECUTABLE "protoc.exe" PATHS "C:\\Program Files" "C:\\Program Files (x86)")
ELSE(MSVC)
  FIND_PROGRAM(PROTOBUF_PROTOC_EXECUTABLE "protoc")
ENDIF(MSVC)

IF(NOT PROTOBUF_PROTOC_EXECUTABLE)
  MESSAGE(FATAL "No Protocol Buffers package found. Get it here: http://code.google.com/apis/protocolbuffers")
ELSE(NOT PROTOBUF_PROTOC_EXECUTABLE)
  MESSAGE(STATUS "Found Protocol Buffers compiler: ${PROTOBUF_PROTOC_EXECUTABLE}")
  EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --version OUTPUT_VARIABLE CURRENT_PROTOC_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
  IF(NOT "${PROTOC_VERSION}" STREQUAL "${CURRENT_PROTOC_VERSION}")
    SET(FORCE_PROTOC_COMPILE TRUE)
    UNSET(PROTOC_VERSION CACHE)
    SET(PROTOC_VERSION ${CURRENT_PROTOC_VERSION} CACHE STRING "Google Protocol Buffer Compiler Version")
  ENDIF()
ENDIF(NOT PROTOBUF_PROTOC_EXECUTABLE)

IF(MSVC)
  FIND_PATH(PROTOBUF_INCLUDE google/protobuf/message.h
    DOC "Google Protocol Buffers include files"
    PATHS ${PROTOBUF_ROOT}/src/ INCLUDE )
  IF(CMAKE_CL_64)
    FIND_LIBRARY(Protobuf_LIBRARY_RELEASE libprotobuf.lib
      DOC "Protocol Buffers C++ libprotobuf (release)"
      PATHS ${PROTOBUF_ROOT}/vsprojects/x64/Release LIB NO_DEFAULT_PATH )
    FIND_LIBRARY(Protobuf_LIBRARY_DEBUG libprotobuf.lib
      DOC "Protocol Buffers C++ libprotobuf (debug)"
      PATHS ${PROTOBUF_ROOT}/vsprojects/x64/Debug LIB NO_DEFAULT_PATH )
    ELSE(CMAKE_CL_64)
      FIND_LIBRARY(Protobuf_LIBRARY_RELEASE libprotobuf.lib
        DOC "Protocol Buffers C++ libprotobuf (release)"
        PATHS ${PROTOBUF_ROOT}/vsprojects/Release LIB NO_DEFAULT_PATH )
      FIND_LIBRARY(Protobuf_LIBRARY_DEBUG libprotobuf.lib
        DOC "Protocol Buffers C++ libprotobuf (debug)"
        PATHS ${PROTOBUF_ROOT}/vsprojects/Debug LIB NO_DEFAULT_PATH )
    ENDIF(CMAKE_CL_64)
  SET(PROTOBUF_LIBRARY optimized ${Protobuf_LIBRARY_RELEASE} debug ${Protobuf_LIBRARY_DEBUG} CACHE STRING "Google Protocol Buffers library" )
ELSE(MSVC)
  FIND_PATH(PROTOBUF_INCLUDE google/protobuf/message.h
    DOC "Google Protocol Buffers include files"
    PATHS ${PROTOBUF_ROOT}/src/ INCLUDE ${INCLUDE_DIR})
  FIND_LIBRARY(PROTOBUF_LIBRARY libprotobuf.a DOC "libprotobuf.a"
    PATHS "/usr/lib" "/usr/lib64" "/usr/local/lib" LIB )
ENDIF(MSVC)
IF(NOT PROTOBUF_INCLUDE OR NOT PROTOBUF_LIBRARY)
  SET(ERROR_MESSAGE "\nCould not find Protocol Buffers.  AT LEAST ONE HEADER or LIBRARY FILE IS MISSING - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Protocol Buffers is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DPROTOBUF_ROOT=<Path to (compiled) protobuf root directory>")
  #MESSAGE(FATAL_ERROR "${ERROR_MESSAGE} ${LIB_ERROR_MESSAGE}")
ELSE(NOT PROTOBUF_INCLUDE OR NOT PROTOBUF_LIBRARY)
  MESSAGE(STATUS "Found Protocol Buffers runtime: " ${PROTOBUF_INCLUDE})
  FILE(GLOB PROTO_FILES RELATIVE ${MAIDSAFE_SOURCE_DIR} "protobuf/*.proto")
  FILE(GLOB TEST_PROTO_FILES RELATIVE ${MAIDSAFE_SOURCE_DIR} "tests/rpcprotocol/*.proto")
  SET(PROTO_FILES ${PROTO_FILES} ${TEST_PROTO_FILES})
  FOREACH(PROTO_FILE ${PROTO_FILES})
    STRING(REGEX REPLACE "[\\/.]" "_" PROTO_CACHE_NAME ${PROTO_FILE})
    GENERATE_PROTO_FILES(${PROTO_FILE} ${PROTO_CACHE_NAME})
  ENDFOREACH()
ENDIF(NOT PROTOBUF_INCLUDE OR NOT PROTOBUF_LIBRARY)

INCLUDE (CheckLibraryExists)
IF (WIN32)
  FIND_PROGRAM (PROTOBUF_PROTOC_EXECUTABLE "protoc.exe" PATHS "C:\\Program Files" "C:\\Program Files (x86)")
ELSE (WIN32)
  FIND_PROGRAM (PROTOBUF_PROTOC_EXECUTABLE "protoc")
ENDIF (WIN32)

IF (NOT PROTOBUF_PROTOC_EXECUTABLE)
  MESSAGE (FATAL "No google protocol buffers package found. Get it here: http://code.google.com/apis/protocolbuffers")
ELSE (NOT PROTOBUF_PROTOC_EXECUTABLE)
  MESSAGE (STATUS "Found google protocol buffers compiler at ${PROTOBUF_PROTOC_EXECUTABLE}")
ENDIF (NOT PROTOBUF_PROTOC_EXECUTABLE)

MESSAGE (STATUS "Check google protocol buffers runtime lib")
IF (MSVC)
  FIND_PATH (PROTOBUF_INCLUDE google/protobuf/message.h
    DOC "Google Protocol Buffers include files"
    PATHS ${PROTOBUF_ROOT}/src/ INCLUDE )
  IF (CMAKE_CL_64)
    FIND_LIBRARY (Protobuf_LIBRARY_RELEASE libprotobuf.lib
      DOC "Protocol Buffers C++ libprotobuf (release)"
      PATHS ${PROTOBUF_ROOT}/vsprojects/x64/Release LIB NO_DEFAULT_PATH )
    FIND_LIBRARY (Protobuf_LIBRARY_DEBUG libprotobuf.lib
      DOC "Protocol Buffers C++ libprotobuf (debug)"
      PATHS ${PROTOBUF_ROOT}/vsprojects/x64/Debug LIB NO_DEFAULT_PATH )
    ELSE (CMAKE_CL_64)
      FIND_LIBRARY (Protobuf_LIBRARY_RELEASE libprotobuf.lib
        DOC "Protocol Buffers C++ libprotobuf (release)"
        PATHS ${PROTOBUF_ROOT}/vsprojects/Release LIB NO_DEFAULT_PATH )
      FIND_LIBRARY (Protobuf_LIBRARY_DEBUG libprotobuf.lib
        DOC "Protocol Buffers C++ libprotobuf (debug)"
        PATHS ${PROTOBUF_ROOT}/vsprojects/Debug LIB NO_DEFAULT_PATH )
    ENDIF (CMAKE_CL_64)
  SET (PROTOBUF_LIBRARY optimized ${Protobuf_LIBRARY_RELEASE} debug ${Protobuf_LIBRARY_DEBUG} CACHE STRING "protocol buffers libary" )
ELSE (MSVC)
  FIND_PATH (PROTOBUF_INCLUDE google/protobuf/message.h
    DOC "Google Protocol Buffers include files"
    PATHS "c:/usr/include" INCLUDE )
  FIND_LIBRARY (PROTOBUF_LIBRARY libprotobuf.a
    DOC "libprotobuf"
    PATHS "/usr/lib" "/usr/lib64" "/usr/local/lib" "c:/usr/lib" LIB )
ENDIF (MSVC)
IF (NOT PROTOBUF_INCLUDE OR NOT PROTOBUF_LIBRARY)
  MESSAGE (FATAL " No google protocol buffers runtime found. Get it here: http://code.google.com/apis/protocolbuffers")
  SET (ERROR_MESSAGE "\nCould not find Protocol Buffers.  AT LEAST ONE HEADER or LIBRARY FILE IS MISSING - ")
  SET (ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET (ERROR_MESSAGE "${ERROR_MESSAGE}If Protocol Buffers is already installed, run:\n")
  SET (ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DPROTOBUF_ROOT=<Path to (compiled) protobuf root directory>")
  MESSAGE (FATAL_ERROR "${ERROR_MESSAGE}")
ELSE (NOT PROTOBUF_INCLUDE OR NOT PROTOBUF_LIBRARY)
  MESSAGE (STATUS "Found google protocol buffers runtime " ${PROTOBUF_INCLUDE})
ENDIF (NOT PROTOBUF_INCLUDE OR NOT PROTOBUF_LIBRARY)

###################################################################################################
# Python library search                                                                           #
###################################################################################################
UNSET(PYTHON_EXECUTABLE CACHE)
INCLUDE(FindPythonInterp)
INCLUDE(FindPythonLibs)
FIND_PACKAGE(PythonInterp)
IF(PYTHONINTERP_FOUND)
  MESSAGE("-- Found python executable: style checking enabled.")
ELSE(PYTHONINTERP_FOUND)
  MESSAGE("-- Didn't find python executable: style checking disabled.")
ENDIF(PYTHONINTERP_FOUND)

FIND_PACKAGE (PythonLibs REQUIRED)

###################################################################################################
# All other libraries search                                                                      #
###################################################################################################
IF(UNIX)
	# IF(NOT CMAKE_BUILD_TYPE MATCHES "Release")
  	SET(SYS_LIB dl pthread)
	# ELSEIF(NOT CMAKE_BUILD_TYPE MATCHES "Release")
	#	SET(SYS_LIB dl pthread)
	# ENDIF(NOT CMAKE_BUILD_TYPE MATCHES "Release")
  IF(NOT APPLE)
    SET(SYS_LIB rt c m ${SYS_LIB})
  ENDIF()
  FOREACH(library ${SYS_LIB})
    FIND_LIBRARY(CURRENT_LIB ${library} ${LIB_DIR})
    IF(CURRENT_LIB)
      MESSAGE("-- Found library ${CURRENT_LIB}")
    ELSE(CURRENT_LIB)
      MESSAGE(FATAL_ERROR "\nCouldn't find library ${library}")
    ENDIF(CURRENT_LIB)
    UNSET(CURRENT_LIB CACHE)
  ENDFOREACH()
ELSEIF(WIN32)
  IF(MSVC)
    SET(SYS_LIB WSock32.lib IPHlpApi.lib)
   # SET(SYS_LIB c:/lib/WSock32.lib c:/lib/IPHlpApi.lib)   These libs seems to be in system path on MSVC
  ELSE(MSVC)
    SET(SYS_LIB advapi32 kernel32 ws2_32 iphlpapi mswsock)
  ENDIF(MSVC)
  FOREACH(library ${SYS_LIB})
    FIND_LIBRARY(CURRENT_LIB ${library} c:/usr/lib)
    IF(CURRENT_LIB)
      MESSAGE("-- Found library ${CURRENT_LIB}")
    ELSE(CURRENT_LIB)
      IF(NOT MSVC)
        MESSAGE(FATAL_ERROR "\nCouldn't find library ${library}")
      ENDIF(NOT MSVC)
    ENDIF(CURRENT_LIB)
    UNSET(CURRENT_LIB CACHE)
  ENDFOREACH()
ENDIF(UNIX)

SET(SYS_LIB ${SYS_LIB} ${Boost_LIBRARIES} ${GLOG_LIB} ${PROTOBUF_LIBRARY} )
INCLUDE_DIRECTORIES(${MAIDSAFE_SOURCE_DIR}  ${INCLUDE_DIR})
INCLUDE_DIRECTORIES(AFTER SYSTEM ${GTEST_INCLUDE_DIRS} ${PROTOBUF_INCLUDE}  ${Boost_INCLUDE_DIRS})
MESSAGE("================================================================================")


# Stephan: I have moved preprocessor defines for MSVC here to have 
#          them with a little more explanation
#          you may consider doing the same for other targets such as MingW
IF(MSVC)
	# these are apparently necessary for MSVC to work
	ADD_DEFINITIONS(-DWIN32_LEAN_AND_MEAN)
	ADD_DEFINITIONS(-D_WIN32_WINNT=0x501)
	
	# This disables bogus warnings of the MS compiler trying to be witty.
	# It annoys and hides real issues, so better keep it
	ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
	
	# This is important! Those switches are necessary for boot to work, and yet 
	# they break ABI compatibility for C++ libs at least in Debug mode.
	# In most 3rd party libs they should be set as well, but if you add one,
	# remember this. SET THOSE VALUES EVERYWHERE YOU CAN!
	ADD_DEFINITIONS(-D_SECURE_SCL=0)
	ADD_DEFINITIONS(-D_HAS_ITERATOR_DEBUGGING=0)

	# prevents std::min() and std::max() to be overwritten
	ADD_DEFINITIONS(-DNOMINMAX)

	# please document us
	ADD_DEFINITIONS(-D__MSVC__)
	ADD_DEFINITIONS(-D__WIN32__)
	ADD_DEFINITIONS(-D_CONSOLE)
	ADD_DEFINITIONS(-D_UNICODE)
ENDIF(MSVC)


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
LIST(REMOVE_ITEM M_UPNP_DIR "${MAIDSAFE_SOURCE_DIR}/upnp/upnpclientimpl.cc")
LIST(REMOVE_ITEM M_UPNP_DIR "${MAIDSAFE_SOURCE_DIR}/upnp/upnpclientimpl.h")
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
LIST(REMOVE_ITEM T_KADEMLIA_DIR "${MAIDSAFE_SOURCE_DIR}/tests/kademlia/testknode.cc")
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
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${MAIDSAFE_SOURCE_DIR}/tests/rpcprotocol/testservices.pb.h")
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${MAIDSAFE_SOURCE_DIR}/tests/rpcprotocol/testservices.pb.cc")
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
# traverse subdirs for imported 3rd party libs                                                    #
###################################################################################################
ADD_SUBDIRECTORY(udt)
#ADD_SUBDIRECTORY(libupnp)
ADD_SUBDIRECTORY(cryptopp)
###################################################################################################
# All Platforms:  Add Test Exes and Create all maidsafe-dht libs                                  #
###################################################################################################
ADD_EXECUTABLE(TESTbase ${T_MAIN} ${T_BASE_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTkademlia ${T_MAIN} ${T_KADEMLIA_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTknode "tests/kademlia/testknode.cc" ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTtransport ${T_MAIN} ${T_TRANSPORT_DIR}  ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTrpcprotocol ${T_MAIN} ${T_RPCPROTO_DIR}  ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTnatpmp ${T_MAIN} ${T_NATPMP_DIR}  ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTupnp ${T_MAIN} ${T_UPNP_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(kaddemo ${T_DEMO_DIR} ${MAIDSAFE_H} )
ADD_EXECUTABLE(kaddemostatic ${T_DEMO_DIR} ${MAIDSAFE_H} )
###Libraries
ADD_LIBRARY(maidsafe SHARED  ${DHT_SOURCE_FILES})
ADD_LIBRARY(maidsafe_static STATIC  ${DHT_SOURCE_FILES})
#Rename maidsafe_static as maidsafe on way out !
SET_TARGET_PROPERTIES(maidsafe_static PROPERTIES OUTPUT_NAME maidsafe)
###################################################################################################
# Builds                                                                                          #
###################################################################################################
IF(MSVC)
	SET(EXTENS .lib)
ELSE(MSVC)
	SET(EXTENS .a)
ENDIF(MSVC)	
SET(LINK_DIRECTORIES ${LIBRARY_OUTPUT_PATH} ${LIB_DIR})

SET(BUILD_SHARED_LIBS OFF)
ADD_DEFINITIONS(-DSTATICLIB)
#Ensure we pick up correct libs and not some older installed on 
IF(NOT MSVC)
	IF(NOT WIN32)
		set_property(TARGET maidsafe PROPERTY IMPORTED_LOCATION bin/libmaidsafe.so)
		set_property(TARGET cryptopp PROPERTY IMPORTED_LOCATION bin/libcryptopp.so)
		set_property(TARGET udt PROPERTY IMPORTED_LOCATION bin/libudt.so)
	ELSE(WIN32)
		set_property(TARGET maidsafe PROPERTY IMPORTED_LOCATION bin/libmaidsafe.dll)
		set_property(TARGET cryptopp PROPERTY IMPORTED_LOCATION bin/libcryptopp.dll)
		set_property(TARGET udt PROPERTY IMPORTED_LOCATION bin/libudt.dll)
	ENDIF(NOT WIN32)
set_property(TARGET maidsafe_static PROPERTY IMPORTED_LOCATION bin/libmaidsafe.a)
set_property(TARGET cryptopp_static PROPERTY IMPORTED_LOCATION bin/libcryptopp.a)
set_property(TARGET udt_static PROPERTY IMPORTED_LOCATION bin/libudt.a)
ELSE(NOT MSVC)
set_property(TARGET maidsafe_static PROPERTY IMPORTED_LOCATION bin/libmaidsafe.lib)
set_property(TARGET maidsafe PROPERTY IMPORTED_LOCATION bin/libmaidsafe.dll)
set_property(TARGET cryptopp_static PROPERTY IMPORTED_LOCATION bin/libcryptopp.lib)
set_property(TARGET cryptopp PROPERTY IMPORTED_LOCATION bin/libcryptopp.dll)
set_property(TARGET udt_static PROPERTY IMPORTED_LOCATION bin/libupnp.lib)
set_property(TARGET udt PROPERTY IMPORTED_LOCATION bin/libupnp.dll)

ENDIF(NOT MSVC)

TARGET_LINK_LIBRARIES(TESTbase maidsafe_static gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTtransport maidsafe_static gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTrpcprotocol maidsafe_static gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_static gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTknode maidsafe_static gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_static gtest ${SYS_LIB} )
TARGET_LINK_LIBRARIES(TESTupnp maidsafe_static gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(maidsafe udt cryptopp ${SYS_LIB})
TARGET_LINK_LIBRARIES(maidsafe_static udt_static  cryptopp_static ${SYS_LIB})
TARGET_LINK_LIBRARIES(kaddemo maidsafe ${DEMO_LIBS} ${SYS_LIB})
TARGET_LINK_LIBRARIES(kaddemostatic maidsafe_static ${DEMO_LIBS} ${SYS_LIB})
###################################################################################################
# Compiler and linker flags - after all targets declared                                          #
###################################################################################################

####APPLE##############################
IF(APPLE)
  SET(CMAKE_AR "/usr/bin/libtool")
  SET(CMAKE_CXX_CREATE_STATIC_LIBRARY "<CMAKE_AR> -static -o <TARGET> <LINK_FLAGS> <OBJECTS>" "<CMAKE_RANLIB> <TARGET>")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DARWIN_C_SOURCE")
  SET(MAIDSAFE_DHT_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finline-functions -funswitch-loops -fgcse-after-reload -ftree-vectorize -D_FORTIFY_SOURCE=2 -DOSX -DBSD -D__FreeBSD__=10 -D_FILE_OFFSET_BITS=64 -DCRYPTOPP_DISABLE_ASM")
  SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wuninitialized")
  #######Coverage and Profiling#############
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  	SET_TARGET_PROPERTIES(maidsafe_static PROPERTIES LINK_FLAGS "-pg -fprofile-arcs -ftest-coverage")
  ENDIF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET_SOURCE_FILES_PROPERTIES(${CRYPTOPP} PROPERTIES COMPILE_FLAGS "-DNDEBUG -g -O2 -DCRYPTOPP_DISABLE_ASM -pipe")
  SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lprotobuf" CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov" CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -lgcov" CACHE INTERNAL "" FORCE)
ENDIF(APPLE)

######LINUX#################################
IF(UNIX AND NOT APPLE)
  SET(MAIDSAFE_DHT_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -fPIC -Wl,-z,relro -Wformat  -Wno-system-headers  -Wformat-security -Wall -finline-functions -funswitch-loops -fgcse-after-reload -ftree-vectorize -fpredictive-commoning -Wextra -Wfloat-equal -Wlong-long -Wredundant-decls -Wstrict-overflow=5 -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -std=c++98 -ansi -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -DMAIDSAFE_LINUX")
  SET(MAIDSAFE_DHT_CXX_FLAGS_DEBUG "${MAIDSAFE_DHT_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG} -fPIC -DDEBUG ") 
  SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${MAIDSAFE_DHT_CXX_FLAGS} ${CMAKE_CXX_FLAGS_RELEASE}  -Wuninitialized")
  #######Coverage and Profiling#############
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  	SET_TARGET_PROPERTIES(maidsafe_static PROPERTIES LINK_FLAGS "-pg -fprofile-arcs -ftest-coverage")
  ENDIF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov" CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -lgcov" CACHE INTERNAL "" FORCE)
  SET(SILENT_BUILD "-w -fPIC -DNDEBUG  -march=native -mtune=native -pipe")
ENDIF(UNIX AND NOT APPLE)

#######WINDOWS##############################
IF(WIN32)
  IF (NOT MSVC)
    SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG -O3 -Wuninitialized")
    SET(MAIDSAFE_DHT_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG  -Wall -Wshadow -Wunused-variable -Wunused-parameter -Wunused-function -Wunused -Wno-system-headers -Wno-deprecated -Woverloaded-virtual -Wwrite-strings")
    SET(MAIDSAFE_DHT_CXX_FLAGS "-mthreads -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
    ##put libs in here that will have no chance of passing tests - 3rd party ONLY !!
    SET(MAIDSAFE_DHT_CXX_FLAGS "${MAIDSAFE_DHT_CXX_FLAGS} -Wall -finline-functions  -DNDEBUG -DWIN32_LEAN_AND_MEAN -D__MINGW__ -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32 -D_WIN32_WINNT=0x0501")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG -DWIN32_LEAN_AND_MEAN -D__MINGW__  -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32 -D_WIN32_WINNT=0x0501") 
    SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp kaddemo kaddemostatic PROPERTIES LINK_FLAGS "-mthreads " )
  #######Coverage and Profiling#############
  IF(NOT CMAKE_BUILD_TYPE MATCHES "Release")
      	SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp PROPERTIES LINK_FLAGS "-lgcov -pg -fprofile-arcs -ftest-coverage")
  ENDIF(NOT CMAKE_BUILD_TYPE MATCHES "Release")
SET(SILENT_BUILD  "-mthreads -w -finline-functions -DNDEBUG -D__MINGW__ -DWIN32 -D_WIN32_WINNT=0x0501 -D_WIN32")

  ENDIF(NOT MSVC)
ENDIF(WIN32)

IF(NOT MSVC)
	SET(CMAKE_CXX_FLAGS "")
	SET(CMAKE_CXX_FLAGS_RELEASE "")
	SET(CMAKE_CXX_FLAGS_DEBUG "")
	IF(CMAKE_BUILD_TYPE MATCHES "Release")
		SET(MAIDSAFE_DHT_CXX_FLAGS "${MAIDSAFE_DHT_CXX_FLAGS} ${MAIDSAFE_DHT_CXX_FLAGS_RELEASE}")
	ELSE()
		SET(MAIDSAFE_DHT_CXX_FLAGS "${MAIDSAFE_DHT_CXX_FLAGS} ${MAIDSAFE_DHT_CXX_FLAGS_DEBUG}")
	ENDIF(CMAKE_BUILD_TYPE MATCHES "Release")
    IF(NOT APPLE)
	    SET_SOURCE_FILES_PROPERTIES(${cryptopp_sources} PROPERTIES COMPILE_FLAGS "-DNDEBUG -O3 -march=native -mtune=native -pipe")
    ENDIF(NOT APPLE)
    	SET_SOURCE_FILES_PROPERTIES(${DHT_SOURCE_FILES} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
    	SET_SOURCE_FILES_PROPERTIES(${T_BASE_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
    	SET_SOURCE_FILES_PROPERTIES(${T_TRANSPORT_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
    	SET_SOURCE_FILES_PROPERTIES(${T_RPCPROTO_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
    	SET_SOURCE_FILES_PROPERTIES(${T_UPNP_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
    	SET_TARGET_PROPERTIES(TESTkademlia TESTknode PROPERTIES COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
	#External libs or where we have not created pimple API files (crypto.cc utils.cc as example)
   	SET_SOURCE_FILES_PROPERTIES(${cryptopp_SOURCES}  PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
   	SET_SOURCE_FILES_PROPERTIES(base/crypto.cc  PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
   	SET_SOURCE_FILES_PROPERTIES(base/utils.cc  PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
   	SET_SOURCE_FILES_PROPERTIES("*boost/*" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
   	SET_SOURCE_FILES_PROPERTIES("*google/protobuf/repeated_field.h" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
   	SET_SOURCE_FILES_PROPERTIES(${M_PROTOBUF_DIR}  PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  	SET_SOURCE_FILES_PROPERTIES("${M_UPNP_DIR}" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  	SET_SOURCE_FILES_PROPERTIES(${M_LIBUPNP_DIR} PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS}")
ENDIF (NOT MSVC)

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
    ADD_TEST(STYLE_CHECK_KAD ${MAIDSAFE_SOURCE_DIR}/cpplint.py ${STYLE_KADEMLIA} ${T_KADEMLIA_DIR} ${T_FUNC_KADEMLIA_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_KAD PROPERTY LABELS Functional Kademlia CodingStyle)
    ADD_TEST(STYLE_CHECK_BASE ${MAIDSAFE_SOURCE_DIR}/cpplint.py ${M_BASE_DIR} ${T_BASE_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_BASE PROPERTY LABELS Functional Base CodingStyle)
    ADD_TEST(STYLE_CHECK_RPC ${MAIDSAFE_SOURCE_DIR}/cpplint.py ${M_RPCPROTO_DIR} ${STYLE_RPCPROTO_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_RPC PROPERTY LABELS Functional RpcProtocol CodingStyle)
  ELSE(UNIX)
    ADD_TEST(STYLE_CHECK finderrorsall.bat)
    SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
  ENDIF(UNIX)
ENDIF(PYTHONINTERP_FOUND)
SET(FOUNDALLTESTS true)
IF(UNIX)
  SET(TEST_EXECUTABLES TESTupnp TESTnatpmp TESTbase TESTknode TESTkademlia TESTtransport TESTrpcprotocol)
ELSE(UNIX)
  SET(TEST_EXECUTABLES TESTupnp.exe TESTnatpmp.exe TESTbase.exe TESTknode.exe TESTkademlia.exe TESTtransport.exe TESTrpcprotocol.exe)
ENDIF(UNIX)
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
  		        SET_PROPERTY(TEST ${tst} PROPERTY LABELS Functional ${label_name})
              SET_PROPERTY(TEST ${tst} PROPERTY TIMEOUT 600)
  		      ELSEIF("${tst}" MATCHES "^BEH_" OR "${tst}" MATCHES "^DISABLED_BEH_")
  		        SET_PROPERTY(TEST ${tst} PROPERTY LABELS Behavioural ${label_name})
              SET_PROPERTY(TEST ${tst} PROPERTY TIMEOUT 60)
            ELSE()
              MESSAGE("")
   		        MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
              MESSAGE("")
   		        MESSAGE(AUTHOR_WARNING "${tst} should be named \"BEH_...\" or \"FUNC_...\" (with an optional \"DISABLED_\" prepended).")
   		        MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
  		      ENDIF()
   		      #MESSAGE("${tst}   ${TEST_EXECUTABLE}   --gtest_filter=*${tst}*   ${label_name}")
#            SET(check_for_repeats_list ${check_for_repeats_list} ${tst})
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
#    FOREACH(current_check ${check_for_repeats_list})
#      FOREACH(check_for_repeats ${check_for_repeats_list})
#        STRING(REGEX MATCH ${current_check} check_for_repeats_result ${check_for_repeats})
#        IF((NOT ${current_check} MATCHES ${check_for_repeats}) AND (check_for_repeats_result))
#          SET(repeated_tests ${repeated_tests} ${current_check})
#        ENDIF()
#      ENDFOREACH()
#    ENDFOREACH()
  ENDIF()
ENDFOREACH()
IF(NOT FOUNDALLTESTS)
  MESSAGE("Run cmake again after make to pick up tests.\n")
  MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
ENDIF()

IF(NOT CMAKE_SUPPRESS_DEVELOPER_WARNINGS)
  IF(DEFINED repeated_tests)
    SET(WARNING_MESSAGE "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    FOREACH(var ${repeated_tests})
      SET(WARNING_MESSAGE "${WARNING_MESSAGE}\nRepeated test name - ${var}")
    ENDFOREACH()
    SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    MESSAGE(AUTHOR_WARNING ${WARNING_MESSAGE})
  MESSAGE("================================================================================")
  ENDIF()
ENDIF()

SET(DART_TESTING_TIMEOUT 2400 CACHE INTERNAL "Maximum time allowed before CTest will kill the test.")
IF(UNIX)
  SET(MEMORYCHECK_COMMAND "/usr/bin/valgrind --show-reachable=no")
ENDIF(UNIX)

###################################################################################################
MESSAGE("")
MESSAGE("Package version is set to \"${pddate}\"")
MESSAGE("================================================================================")
MESSAGE("Tests included: \"${MAIDSAFE_TEST_TYPE}\"")
MESSAGE("    To include all tests,          cmake ../.. -DMAIDSAFE_TEST_TYPE=_")
MESSAGE("    To include behavioural tests,  cmake ../.. -DMAIDSAFE_TEST_TYPE=BEH")
MESSAGE("    To include functional tests,   cmake ../.. -DMAIDSAFE_TEST_TYPE=FUNC")
MESSAGE("================================================================================")
MESSAGE("Build type is set to \"${CMAKE_BUILD_TYPE}\"")
MESSAGE("    To alter this (e.g. to Debug), cmake ../.. -DCMAKE_BUILD_TYPE=Debug")
MESSAGE("    Options are Release, Debug, RelWithDebInfo, MinSizeRel")
MESSAGE("================================================================================")
MESSAGE("")

SET(PROTOBUF_INSTALL_FILES protobuf/signed_kadvalue.pb.h protobuf/kademlia_service_messages.pb.h protobuf/contact_info.pb.h protobuf/general_messages.pb.h)

IF (MSVC)
	INSTALL (TARGETS maidsafe maidsafe_static
		RUNTIME DESTINATION bin
		LIBRARY DESTINATION bin
		ARCHIVE DESTINATION lib
		CONFIGURATIONS Release
		)
	INSTALL (FILES ${MAIDSAFE_H} ${PROTOBUF_INSTALL_FILES}
		DESTINATION include/maidsafe
		CONFIGURATIONS Release
		)
ELSE (MSVC)
	INSTALL	(TARGETS maidsafe maidsafe_static
		RUNTIME DESTINATION bin
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
                CONFIGURATIONS Release
	)
	INSTALL (FILES ${MAIDSAFE_H} ${PROTOBUF_INSTALL_FILES}
		DESTINATION include/maidsafe
                CONFIGURATIONS Release
		)
ENDIF (MSVC)

SET(CPACK_PACKAGE_VERSION_PATCH ${pddate})
SET(CPACK_PACKAGE_VERSION "0.1.${pddate}")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "1")
SET(CPACK_PACKAGE_NAME "maidsafe")
SET(CPACK_PACKAGE_CONTACT "info@maidsafe.net")
SET(CPACK_PACKAGE_VENDOR "Maidsafe.net")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Perpetual Data - Client and Vault applications")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "Maidsafe")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${MAIDSAFE_SOURCE_DIR}/../docs/description.txt")
SET(CPACK_RESOURCE_FILE_LICENSE "${MAIDSAFE_SOURCE_DIR}/../docs/LICENSE.txt")
SET(CPACK_RESOURCE_FILE_README "${MAIDSAFE_SOURCE_DIR}/../docs/readme.txt")
SET(CPACK_RESOURCE_FILE_WELCOME "${MAIDSAFE_SOURCE_DIR}/../docs/welcome.txt")

MESSAGE("Install directory is set to \"${CPACK_PACKAGE_INSTALL_DIRECTORY}\"")
MESSAGE("================================================================================")

IF(UNIX)
	SET(CMAKE_INSTALL_PREFIX "/usr")
  SET(CPACK_SET_DESTDIR on)
  SET(CPACK_GENERATOR DEB;RPM;TGZ)
ELSE()
  SET(CPACK_GENERATOR ZIP)
ENDIF()
INCLUDE(CPack)
