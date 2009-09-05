cmake_minimum_required(VERSION 2.6)
#this needs to be at the top of the file
MESSAGE ("================================================================================")
IF(NOT CMAKE_GEN)
  MESSAGE("")
  IF(UNIX)
    MESSAGE("No generator previously specified.  Use e.g. -G\"CodeBlocks - Unix Makefiles\"")
  ELSE(UNIX)
    MESSAGE("No generator previously specified.  Use e.g. -G\"CodeBlocks - MinGW Makefiles\"")
  ENDIF(UNIX)
  MESSAGE("")
ENDIF(NOT CMAKE_GEN)
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)

IF(NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE "Release" CACHE INTERNAL "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)
project (maidsafe-dht)
IF(NOT MAIDSAFE_TEST_TYPE)
   SET(MAIDSAFE_TEST_TYPE "BEH" CACHE INTERNAL "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
ENDIF(NOT MAIDSAFE_TEST_TYPE)

IF(UNIX)
	EXEC_PROGRAM(date ARGS +%a%d%m%y OUTPUT_VARIABLE pddate)
ELSE(UNIX)
	EXEC_PROGRAM("c:\\msys\\1.0\\bin\\date.exe" ARGS +%a%d%m%y OUTPUT_VARIABLE pddate)
ENDIF(UNIX)

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  MESSAGE ("")
  MESSAGE("Building a package which is OK to release.")
  MESSAGE("------------------------------------------")
  SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Release/bin/)
  SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Release/lib)
ELSE()
  SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Debug/bin/)
  SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Debug/lib)
  MESSAGE ("")
  MESSAGE("Building a package which is NOT OK to release.")
  MESSAGE("----------------------------------------------")
 	SET(pddate "DEVELOPER_${pddate}")
ENDIF()

IF(NOT BOOST_VERSION)
   SET(BOOST_VERSION "1_40" CACHE INTERNAL "Set boost version i.e. 1_40 (use an underscore)" FORCE)
ENDIF(NOT BOOST_VERSION)
MESSAGE ("================================================================================")
MESSAGE ("")
IF(${BOOST_VERSION} MATCHES "none")
  MESSAGE ("Boost version is not set.")
  SET(BOOST_VERSION "")
ELSE(${BOOST_VERSION} MATCHES "none")
  MESSAGE ("Boost version is set to \"${BOOST_VERSION}\"")
  SET(BOOST_VERSION "-${BOOST_VERSION}")
ENDIF(${BOOST_VERSION} MATCHES "none")
MESSAGE ("")
MESSAGE ("    To alter this (e.g. for Boost 1.40.x),      cmake ../.. -DBOOST_VERSION=1_40")
MESSAGE ("    To have no Boost version set,               cmake ../.. -DBOOST_VERSION=none")

IF(NOT BOOST_INCLUDES)
	IF(WIN32)
    SET(BOOST_INCLUDES "c:\\usr\\include\\boost${BOOST_VERSION}" CACHE INTERNAL "Set location of BOOST headers eg c:\\usr\\include\\boost${BOOST_VERSION}" FORCE)
	ELSE()
    SET(BOOST_INCLUDES "/usr/include/boost/" CACHE INTERNAL "Set location of BOOST headers eg /usr/include/boost/" FORCE)
	ENDIF()
ENDIF(NOT BOOST_INCLUDES)
MESSAGE ("================================================================================")
MESSAGE ("")
MESSAGE ("Boost include is set to \"${BOOST_INCLUDES}\"")
MESSAGE ("")
IF(UNIX)
  MESSAGE ("    To alter this, e.g.   cmake ../.. -DBOOST_INCLUDES=/usr/include/boost-1_40")
ELSE(UNIX)
  MESSAGE ("    To alter this, e.g.   cmake ../.. -DBOOST_INCLUDES=c:\\usr\\include\\boost-1_40")
ENDIF(UNIX)
MESSAGE ("================================================================================")
MESSAGE ("")
IF(CMAKE_COMPILER_IS_GNUCC)
  IF(NOT GCC_VERSION)
    SET(GCC_VERSION "gcc43" CACHE INTERNAL "Set GCC version e.g. gcc44 (for GCC version 4.4.x)" FORCE)
  ENDIF(NOT GCC_VERSION)
  IF(${GCC_VERSION} MATCHES "none")
    MESSAGE ("GCC version is not set.")
    SET(GCC_VERSION "")
  ELSE(${GCC_VERSION} MATCHES "none")
    MESSAGE ("GCC version is set to \"${GCC_VERSION}\"")
    SET(GCC_VERSION "-${GCC_VERSION}")
  ENDIF(${GCC_VERSION} MATCHES "none")
  MESSAGE ("")
  MESSAGE ("    To alter this (e.g. for GCC 4.4.x),          cmake ../.. -DGCC_VERSION=gcc44") 
  MESSAGE ("    To have no GCC version set,                   cmake ../.. -DGCC_VERSION=none")
  MESSAGE ("================================================================================")
 #MESSAGE ("")
  IF(${CMAKE_GENERATOR} MATCHES "MinGW Makefiles")
    STRING(REPLACE "gcc" "mgw" GCC_VERSION "${GCC_VERSION}")
  ENDIF(${CMAKE_GENERATOR} MATCHES "MinGW Makefiles")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

#############################################################
#Searching for Google Glog Library (logging)#################
#Only in UNIX, since currently it cannont be compiled #######
#On Windows with MinGW#######################################
#############################################################

INCLUDE(CheckIncludeFileCXX)
IF(UNIX)
  FIND_LIBRARY(GLOG_LIB NAMES libglog.a glog)
  CHECK_INCLUDE_FILE_CXX(glog/logging.h GLOG_INCLUDE)
  IF(GLOG_LIB AND GLOG_INCLUDE)
    SET(HAVE_GLOG TRUE)
  ELSE(GLOG_LIB AND GLOG_INCLUDE)
    SET(HAVE_GLOG FALSE)
  ENDIF(GLOG_LIB AND GLOG_INCLUDE)
ELSE(UNIX)
  SET(HAVE_GLOG FALSE)
ENDIF(UNIX)

#Writing the config.h file

CONFIGURE_FILE(${maidsafe-dht_SOURCE_DIR}/config.h.in ${maidsafe-dht_SOURCE_DIR}/maidsafe/config.h)

set(CPACK_PACKAGE_VERSION_PATCH ${pddate})

set(CPACK_PACKAGE_VERSION "0.1.${pddate}")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "1")
#CMake Options
#SET(CMAKE_VERBOSE_MAKEFILE TRUE)
set(Boost_USE_STATIC_LIBS ON)
set(BUILD_SHARED_LIBS OFF)
###################################################################################
#Set up extra includes and libs for windows - it puts them everywhere #############
###################################################################################
IF (WIN32)
	IF(MSVC)
	set(INCLUDE_DIR c:/include/)
	set(LIB_DIR c:/lib/ )
	ELSE(MSVC)
	set(INCLUDE_DIR c:/usr/include/)
	link_directories(c:/MinGW/lib/ c:/MinGW/mingw32/lib/ c:/usr/lib/ ${PROJECT_BINARY_DIR}/Debug/lib)
	ENDIF(MSVC)
ENDIF(WIN32)
INCLUDE_DIRECTORIES(${maidsafe-dht_SOURCE_DIR} ${maidsafe-dht_SOURCE_DIR}/libupnp  ${INCLUDE_DIR} ${BOOST_INCLUDES})
#########################################################################################################
#SET UP ALL FILES AS GLOBS ##############################################################################
#########################################################################################################
#########################################################################################################
####	CODE	####
#FILE(GLOB_RECURSE M_LIBUPNP_C "libupnp/*.c*")
#FILE(GLOB_RECURSE M_LIBUPNP_H "libupnp/*.h*")
#LIST(APPEND M_LIBUPNP_DIR libupnp/igd_desc_parse.c libupnp/miniupnpc.c libupnp/minixml.c libupnp/minisoap.c libupnp/miniwget.c libupnp/upnpc.c libupnp/upnpcommands.c libupnp/upnpreplyparse.c libupnp/testminixml.c libupnp/minixmlvalid.c libupnp/testupnpreplyparse.c libupnp/minissdpc.c libupnp/upnperrors.c libupnp/testigddescparse.c)
LIST(APPEND M_LIBUPNP_DIR libupnp/igd_desc_parse.c  libupnp/minixml.c libupnp/minisoap.c libupnp/miniwget.c  libupnp/upnpcommands.c libupnp/upnpreplyparse.c libupnp/testupnpreplyparse.c  libupnp/upnperrors.c libupnp/miniupnpc.c libupnp/minissdpc.c)
#message("here it is" ${M_LIBUPNP_DIR})
FILE(GLOB M_UPNP_C "upnp/*.c*")
FILE(GLOB M_UPNP_H "upnp/*.h*")
LIST(APPEND M_UPNP_DIR ${M_UPNP_C} ${M_UPNP_H})
LIST(REMOVE_ITEM M_UPNP_DIR "${maidsafe-dht_SOURCE_DIR}/upnp/upnpclientimpl.cc")
LIST(REMOVE_ITEM M_UPNP_DIR "${maidsafe-dht_SOURCE_DIR}/upnp/upnpclientimpl.h")
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
FILE(GLOB M_UDT_C "udt/*.h*")
FILE(GLOB M_UDT_H "udt/*.c*")
LIST(APPEND M_TRANSPORT_DIR ${M_TRANSPORT_C} ${M_TRANSPORT_H} ${M_UDT_C} ${M_UDT_H})
FILE(GLOB MAIDSAFE_C "maidsafe/*.c*")
FILE(GLOB MAIDSAFE_H "maidsafe/*.h*")
LIST(APPEND MAIDSAFE_DIR ${MAIDSAFE_C} ${MAIDSAFE_H})
####	TESTS	####
FILE(GLOB T_BASE_C "tests/base/*.c*")
FILE(GLOB T_BASE_H "tests/base/*.h*")
LIST(APPEND T_BASE_DIR ${T_BASE_C} ${T_BASE_H})
FILE(GLOB T_KADEMLIA_C "tests/kademlia/*.c*")
FILE(GLOB T_KADEMLIA_H "tests/kademlia/*.h*")
LIST(APPEND T_KADEMLIA_DIR ${T_KADEMLIA_C} ${T_KADEMLIA_H})
LIST(REMOVE_ITEM T_KADEMLIA_DIR "${maidsafe-dht_SOURCE_DIR}/tests/kademlia/testknode.cc")
FILE(GLOB T_TRANSPORT_C "tests/transport/*.c*")
FILE(GLOB T_TRANSPORT_H "tests/transport/*.h*")
LIST(APPEND T_TRANSPORT_DIR ${T_TRANSPORT_C} ${T_TRANSPORT_H})
FILE(GLOB T_MAIN  "tests/main.cc")
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
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${maidsafe-dht_SOURCE_DIR}/tests/rpcprotocol/testservices.pb.h")
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${maidsafe-dht_SOURCE_DIR}/tests/rpcprotocol/testservices.pb.cc")
FILE(GLOB T_UPNP_C "tests/upnp/*.c*")
FILE(GLOB T_UPNP_H "tests/upnp/*.h*")
LIST(APPEND T_UPNP_DIR ${T_UPNP_C} ${T_UPNP_H})
FILE(GLOB T_FUNC_KADEMLIA_C "tests/functionalkademlia/*.c*")
FILE(GLOB T_FUNC_KADEMLIA_H "tests/functionalkademlia/*.h*")
LIST(APPEND T_FUNC_KADEMLIA_DIR ${T_FUNC_KADEMLIA_C} ${T_FUNC_KADEMLIA_H})
LIST(REMOVE_ITEM T_FUNC_KADEMLIA_DIR "tests/kademlia/testknode.cc")
FILE(GLOB CRYPTOPP_C "cryptopp/*.c*")
FILE(GLOB CRYPTOPP_H "cryptopp/*.h*")
LIST(APPEND CRYPTOPP ${CRYPTOPP_C} ${CRYPTOPP_H})
FILE(GLOB T_DEMO_C "tests/demo/*.c*")
FILE(GLOB T_DEMO_H "tests/demo/*.h*")
LIST(APPEND T_DEMO_DIR ${T_DEMO_C} ${T_DEMO_H})
#######################################################################################
#All Platforms:  Add Test Exes and Create all maidsafe-dht libs                       #
#######################################################################################
add_executable(TESTbase ${T_MAIN} ${T_BASE_DIR} ${MAIDSAFE_DIR} )
add_executable(TESTkademlia ${T_MAIN} ${T_KADEMLIA_DIR} ${MAIDSAFE_DIR})
#add_executable(TESTfunctionalkademlia ${T_MAIN} ${T_FUNC_KADEMLIA_DIR})
add_executable(TESTknode "tests/kademlia/testknode.cc" ${MAIDSAFE_DIR})
add_executable(TESTtransport ${T_MAIN} ${T_TRANSPORT_DIR} ${MAIDSAFE_DIR})
add_executable(TESTrpcprotocol ${T_MAIN} ${T_RPCPROTO_DIR} ${MAIDSAFE_DIR})
add_executable(TESTupnp ${T_UPNP_DIR} ${MAIDSAFE_DIR})
add_executable(kaddemo ${T_DEMO_DIR})
#######################################################################################
#######################################################################################
add_library(maidsafe-dht STATIC ${M_BASE_DIR} ${M_KADEMLIA_DIR} ${M_TRANSPORT_DIR} ${M_PROTOBUF_DIR} ${M_RPCPROTO_DIR} ${M_LIBUPNP_DIR} ${M_UPNP_DIR} ${MAIDSAFE_DIR} ${CRYPTOPP} ) 
#######################################################################################
#Set up some extra compiler and linker flags for the tests mainly                     #
#######################################################################################
SET_TARGET_PROPERTIES(maidsafe-dht PROPERTIES COMPILE_FLAGS "-D__STDC_LIMIT_MACROS" )
#######################################################################################
#BUILDS
IF (APPLE)
	SET(SYS_LIB 
boost_thread-xgcc40-mt${BOOST_VERSION}.a 
/usr/lib/libprotobuf.a 
boost_system-xgcc40-mt${BOOST_VERSION}.a
boost_filesystem-xgcc40-mt${BOOST_VERSION}.a
boost_regex-xgcc40-mt${BOOST_VERSION}.a
boost_date_time-xgcc40-mt${BOOST_VERSION}.a
dl 
pthread
)
SET(DEMO_LIBS boost_program_options-xgcc40-mt${BOOST_VERSION})
IF(HAVE_GLOG)
  SET(SYS_LIB "${SYS_LIB};/usr/lib/libglog.a")
ENDIF(HAVE_GLOG)
ELSEIF (UNIX AND NOT APPLE)
	SET(SYS_LIB
        /usr/lib/libboost_thread${GCC_VERSION}-mt${BOOST_VERSION}.a
        /usr/lib/libprotobuf.a
        /usr/lib/libboost_system${GCC_VERSION}-mt${BOOST_VERSION}.a
        /usr/lib/libboost_filesystem${GCC_VERSION}-mt${BOOST_VERSION}.a
        /usr/lib/libboost_regex${GCC_VERSION}-mt${BOOST_VERSION}.a
        /usr/lib/libboost_date_time${GCC_VERSION}-mt${BOOST_VERSION}.a
        rt
        c
        m
        dl
        pthread
		)
	IF(HAVE_GLOG)
		SET(SYS_LIB "${SYS_LIB};/usr/lib/libglog.a")
	ENDIF(HAVE_GLOG)
	SET(DEMO_LIBS
/usr/lib/libboost_program_options${GCC_VERSION}-mt${BOOST_VERSION}.a
)

ELSEIF (WIN32)
	IF(MSVC)
		set(SYS_LIB c:/lib/libprotobuf.lib c:/lib/libboost_system-vc90-mt-1_36.lib c:/lib/libboost_filesystem-vc90-mt-1_36.lib  c:/lib/libboost_regex-vc90-mt-1_36.lib  c:/lib/libboost_thread-vc90-mt-1_36.lib c:/lib/libboost_date_time-vc90-mt-1_36.lib c:/lib/WSock32.lib c:/lib/IPHlpApi.lib)
		SET(DEMO_LIBS c:/lib/boost_program_options-vc90-mt-1_36.lib)
	ELSE(MSVC)
		SET(SYS_LIB
		 -ladvapi32 
		 -lkernel32 
		 -mi386pe
		-lstdc++
		-lws2_32
		c:/usr/lib/libboost_system${GCC_VERSION}-mt${BOOST_VERSION}.lib
		c:/usr/lib/libboost_filesystem${GCC_VERSION}-mt${BOOST_VERSION}.lib
		c:/usr/lib/libboost_regex${GCC_VERSION}-mt${BOOST_VERSION}.lib
		c:/usr/lib/libboost_thread${GCC_VERSION}-mt${BOOST_VERSION}.lib
		c:/usr/lib/libboost_date_time${GCC_VERSION}-mt${BOOST_VERSION}.lib
		c:/usr/lib/dokan.lib
		c:/usr/lib/libprotobuf.a  -liphlpapi
		)
		SET(DEMO_LIBS c:/usr/lib/libboost_program_options${GCC_VERSION}-mt${BOOST_VERSION}.lib)
	ENDIF(MSVC)
ENDIF(APPLE)
TARGET_LINK_LIBRARIES(TESTbase  maidsafe-dht  protobuf  gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTtransport maidsafe-dht gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTrpcprotocol maidsafe-dht gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTkademlia maidsafe-dht gtest  ${SYS_LIB} )
TARGET_LINK_LIBRARIES(TESTknode maidsafe-dht  gtest ${SYS_LIB} )
TARGET_LINK_LIBRARIES(TESTupnp maidsafe-dht gtest ${SYS_LIB} )
TARGET_LINK_LIBRARIES(maidsafe-dht  ${SYS_LIB} )
TARGET_LINK_LIBRARIES(kaddemo maidsafe-dht ${DEMO_LIBS})

##################################################################################
# COMPILER FLAGS  - here after all targets declared                              #
##################################################################################
IF (APPLE)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -finline-functions -funswitch-loops -fgcse-after-reload -ftree-vectorize -D_FORTIFY_SOURCE=2 -DOSX -DBSD -D__FreeBSD__=10  -D_FILE_OFFSET_BITS=64" )
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -O0 -pg -fprofile-arcs -ftest-coverage" )
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wuninitialized ")
  SET(TARGET_PROPERTIES_DEBUG TESTbase TESTknode TESTkademlia TESTtransport TESTrealmaidsafe TESTrealkademlia  LINK_FLAGS -fprofile-arcs -ftest-coverage)
 ## SET_TARGET_PROPERTIES(maidsafe-dht  PROPERTIES COMPILE_FLAGS -w )
ELSEIF (UNIX AND NOT APPLE)
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -O0 -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wuninitialized ")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_RELEASE} -O2 ")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}   -funswitch-loops -fgcse-after-reload -ftree-vectorize -fpredictive-commoning -Wextra -Wall  -Wextra -Wfloat-equal -Wlong-long  -Wredundant-decls -Wstrict-overflow=5   -Wredundant-decls -Wunused-function  -Wunused-label  -Wunused-parameter -Wunused-value -Wunused-variable -std=c++98 -Wall -ansi -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
  ##put libs in here that will have no chance of passing tests - 3rd party ONLY !!
  #SET_TARGET_PROPERTIES(PDpbmsgslib PDupnplib PDtransportlib maidsafe-dht  PROPERTIES COMPILE_FLAGS -w )
  SET_TARGET_PROPERTIES( maidsafe-dht  PROPERTIES COMPILE_FLAGS -w )
ELSEIF (WIN32)
IF(MSVC)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DUNICODE /D_UNICODE /D_WIN32_WINDOWS /D_CONSOLE /D__MSVC__")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} /DUNICODE /D_WIN32_WINDOWS /DDEBUG /D_CONSOLE")
ELSE(MSVC)
	#SET(CTEST_COVERAGE_COMMAND c:/MinGW/bin/gcov.exe)
	## SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -O0 -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized ")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -O0")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w -D_FORTIFY_SOURCE=2 -fno-stack-protector  -D_FILE_OFFSET_BITS=64")
  ##put libs in here that will have no chance of passing tests - 3rd party ONLY !!
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -DNDEBUG -DSTATICLIB  -DWIN32_LEAN_AND_MEAN  -D__MINGW__  -L c:/MinGW/lib/ -L c:/MinGW/mingw32/lib/ -static   -mthreads -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32  -D_WIN32_WINNT=0x0501  -mthreads ")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG -DSTATICLIB  -DWIN32_LEAN_AND_MEAN  -D__MINGW__  -L c:/MinGW/lib/ -L c:/MinGW/mingw32/lib/ -static   -mthreads -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32  -D_WIN32_WINNT=0x0501  -mthreads ")
  #SET_TARGET_PROPERTIES(PDpbmsgslib PDupnplib PDtransportlib maidsafe-dht  PROPERTIES COMPILE_FLAGS -w )
  SET_TARGET_PROPERTIES( maidsafe-dht  PROPERTIES COMPILE_FLAGS -w )
ENDIF(MSVC)
ENDIF(APPLE)
##temporarily suppress compilation warnings before warnings are taken out from upnp code
#SET_TARGET_PROPERTIES(TESTupnp PDupnplib PROPERTIES COMPILE_FLAGS -w )
#SET_TARGET_PROPERTIES(PDtransportlib PROPERTIES COMPILE_FLAGS -finline-functions)

################################################################
# TESTS                                                        #
################################################################
INCLUDE(CTest)
SET(CTEST_CUSTOM_MAXIMUM_PASSED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CUSTOM_MAXIMUM_FAILED_TEST_OUTPUT_SIZE 50000)
SET (CTEST_CONTINUOUS_DURATION 600)
SET (CTEST_CONTINUOUS_MINIMUM_INTERVAL 10)
set(CTEST_START_WITH_EMPTY_BINARY_DIRECTORY true)
ADD_TEST(TESTupnp ${EXECUTABLE_OUTPUT_PATH}/TESTupnp)
IF(UNIX)
ADD_TEST(CHK_KAD ${maidsafe-dht_SOURCE_DIR}/cpplint.py ${STYLE_KADEMLIA} ${T_KADEMLIA_DIR} ${T_FUNC_KADEMLIA_DIR})
ADD_TEST(CHK_BASE ${maidsafe-dht_SOURCE_DIR}/cpplint.py ${M_BASE_DIR} ${T_BASE_DIR})
ADD_TEST(CHK_RPC ${maidsafe-dht_SOURCE_DIR}/cpplint.py ${M_RPCPROTO_DIR} ${STYLE_RPCPROTO_DIR})
#ADD_TEST(Knode ${EXECUTABLE_OUTPUT_PATH}/TESTknode)
ENDIF(UNIX)
IF(WIN32)
#ADD_TEST(Knode ${EXECUTABLE_OUTPUT_PATH}/TESTknode.exe)
ENDIF()
IF(UNIX)
	FOREACH(TESTTYPE TESTbase TESTknode  TESTkademlia TESTtransport TESTrpcprotocol)
	#FOREACH(TESTTYPE TESTfs TESTbase TESTknode  TESTkademlia TESTfunctionalkademlia TESTtransport TESTrpcprotocol)
ELSE(UNIX)
	FOREACH(TESTTYPE TESTbase.exe TESTknode.exe TESTkademlia.exe TESTtransport.exe  TESTrpcprotocol.exe)
	#FOREACH(TESTTYPE TESTbase.exe TESTknode.exe TESTkademlia.exe TESTfunctionalkademlia.exe TESTtransport.exe  TESTrpcprotocol.exe)
ENDIF(UNIX)
	EXEC_PROGRAM(${EXECUTABLE_OUTPUT_PATH}/${TESTTYPE} ARGS --gtest_list_tests OUTPUT_VARIABLE maid_tests)
	if(WIN32)
	STRING(REPLACE "\n" ";" maid_tests "${maid_tests}")
	STRING(REPLACE " " "" maid_tests "${maid_tests}")
	#STRING(REPLACE " " ";" TESTTYPE "${TESTTYPE}")
	ELSE(WIN32)
	STRING(REPLACE "\n" ";" maid_tests "${maid_tests}")
	STRING(REPLACE " " "" maid_tests "${maid_tests}")
	STRING(REPLACE " " ";" TESTTYPE "${TESTTYPE}")
	ENDIF(WIN32)

	FOREACH(tst ${maid_tests})
			IF(NOT "${tst}" MATCHES "(profiling).+")
			IF(NOT "${tst}" MATCHES "(\\.$)")
			IF("${tst}" MATCHES "(${MAIDSAFE_TEST_TYPE}).+")
		    ADD_TEST(${tst}    ${EXECUTABLE_OUTPUT_PATH}/${TESTTYPE}   --gtest_filter=*${tst}*)
		    #		    message("${tst}   ${TESTTYPE}    --gtest_filter=*${tst}*")
	    		ENDIF()
	    		ENDIF()
			ENDIF()
	ENDFOREACH()
ENDFOREACH()

SET(DART_TESTING_TIMEOUT 3500)
IF(UNIX)
SET(MEMORYCHECK_COMMAND "/usr/bin/valgrind --show-reachable=no")
ENDIF(UNIX)

################################################################
MESSAGE ("Package version is set to \"${pddate}\"")
MESSAGE ("================================================================================")
MESSAGE ("")
MESSAGE ("Tests included: \"${MAIDSAFE_TEST_TYPE}\"")
MESSAGE ("")
MESSAGE ("    To include all tests,                     cmake ../.. -DMAIDSAFE_TEST_TYPE=_")
MESSAGE ("    To include behavioural tests,           cmake ../.. -DMAIDSAFE_TEST_TYPE=BEH")
MESSAGE ("    To include functional tests,           cmake ../.. -DMAIDSAFE_TEST_TYPE=FUNC")
MESSAGE ("================================================================================")
MESSAGE ("")
MESSAGE ("Build type is set to \"${CMAKE_BUILD_TYPE}\"")
MESSAGE ("")
MESSAGE ("    To alter this (e.g. to Debug),          cmake ../.. -DCMAKE_BUILD_TYPE=Debug")
MESSAGE ("    Options are Release, Debug, RelWithDebInfo, MinSizeRel")
MESSAGE ("================================================================================")
MESSAGE ("")

install(FILES maidsafe/maidsafe-dht.h maidsafe/maidsafe-dht_config.h
maidsafe/utils.h maidsafe/crypto.h maidsafe/routingtable.h
maidsafe/alternativestore.h protobuf/signed_kadvalue.pb.h
protobuf/kademlia_service_messages.pb.h protobuf/contact_info.pb.h
protobuf/general_messages.pb.h maidsafe/online.h maidsafe/config.h
        DESTINATION /usr/include/maidsafe)
install(TARGETS maidsafe-dht
        ARCHIVE
        DESTINATION /usr/lib/)

set(CPACK_PACKAGE_NAME "maidsafe-dht")
set(CPACK_PACKAGE_CONTACT "info@maidsafe.net")
set(CPACK_PACKAGE_VENDOR "Maidsafe.net")
 set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Perpetual Data - Client and Vault applications")
 set(CPACK_PACKAGE_INSTALL_DIRECTORY "Maidsafe")
 set(CPACK_PACKAGE_DESCRIPTION_FILE "${maidsafe-dht_SOURCE_DIR}/../docs/description.txt")
 set(CPACK_RESOURCE_FILE_LICENSE "${maidsafe-dht_SOURCE_DIR}/../docs/LICENSE.txt")
 set(CPACK_RESOURCE_FILE_README "${maidsafe-dht_SOURCE_DIR}/../docs/readme.txt")
 set(CPACK_RESOURCE_FILE_WELCOME "${maidsafe-dht_SOURCE_DIR}/../docs/welcome.txt")

MESSAGE ("Install directory is set to \"${CPACK_PACKAGE_INSTALL_DIRECTORY}\"")
MESSAGE ("================================================================================")
MESSAGE ("")

IF(UNIX)
	SET(CMAKE_INSTALL_PREFIX "/usr")
  SET(CPACK_SET_DESTDIR on)
  SET(CPACK_GENERATOR DEB;RPM;TGZ)
ELSE()

  SET(CPACK_GENERATOR ZIP)
ENDIF()
INCLUDE(CPack)
