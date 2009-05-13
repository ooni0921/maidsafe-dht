cmake_minimum_required(VERSION 2.6)
#this needs to be at the top of the file
message ("#############################################")
IF(NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)

project (maidsafe-dht)

IF(NOT MAIDSAFE_TEST_TYPE)
   SET(MAIDSAFE_TEST_TYPE "BEH" CACHE STRING "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
ENDIF(NOT MAIDSAFE_TEST_TYPE)

if(UNIX)
	EXEC_PROGRAM(date ARGS +%a%d%m%y OUTPUT_VARIABLE pddate)
ELSE(UNIX)
	EXEC_PROGRAM("c:\\msys\\1.0\\bin\\date.exe" ARGS +%a%d%m%y OUTPUT_VARIABLE pddate)
ENDIF(UNIX)

IF(CMAKE_BUILD_TYPE MATCHES "Release")
message("building an ok to release package")
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Release/bin/)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Release/lib)
ELSE()
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Debug/bin/)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Debug/lib)
message("building a not for release package")
	SET(pddate "DEVELOPER_${pddate}")
ENDIF()


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
INCLUDE_DIRECTORIES(${maidsafe-dht_SOURCE_DIR} ${INCLUDE_DIR} )
##################################################################################
#SET UP ALL FILES AS GLOBS #######################################################
##################################################################################
FILE(GLOB M_PROTOBUF_C "protobuf/*.c*")                            #
FILE(GLOB M_PROTOBUF_H "protobuf/*.h*")                            #
LIST(APPEND M_PROTOBUF_DIR ${M_PROTOBUF_C} ${M_PROTOBUF_H})                      #
FILE(GLOB M_BASE_C "base/*.c*")                                    #
FILE(GLOB M_BASE_H "base/*.h*")                                    #
LIST(APPEND M_BASE_DIR ${M_BASE_C} ${M_BASE_H})                                  #
FILE(GLOB M_KADEMLIA_C "kademlia/*.c*")                            #
FILE(GLOB M_KADEMLIA_H "kademlia/*.h*")                            #
LIST(APPEND M_KADEMLIA_DIR ${M_KADEMLIA_C} ${M_KADEMLIA_H})                      #
LIST(APPEND STYLE_KADEMLIA ${M_KADEMLIA_C} ${M_KADEMLIA_H})                      #
FILE(GLOB PB_KADEMLIA "kademlia/*.pb.*")                           #
FILE(GLOB M_TRANSPORT_C "transport/*.c*")                          #
FILE(GLOB M_TRANSPORT_H "transport/*.h*")                          #
FILE(GLOB M_UDT_C "udt/*.h*")                          #
FILE(GLOB M_UDT_H "udt/*.c*")                          #
LIST(APPEND M_TRANSPORT_DIR ${M_TRANSPORT_C} ${M_TRANSPORT_H} ${M_UDT_C} ${M_UDT_H})                   #
FILE(GLOB T_BASE_C "tests/base/*.c*")                              #
FILE(GLOB T_BASE_H "tests/base/*.h*")                              #
LIST(APPEND T_BASE_DIR ${T_BASE_C} ${T_BASE_H})                                  #
FILE(GLOB T_KADEMLIA_C "tests/kademlia/*.c*")                      #
FILE(GLOB T_KADEMLIA_H "tests/kademlia/*.h*")                      #
LIST(APPEND T_KADEMLIA_DIR ${T_KADEMLIA_C} ${T_KADEMLIA_H})                      #
FILE(GLOB T_TRANSPORT_C "tests/transport/*.c*")                    #
FILE(GLOB T_TRANSPORT_H "tests/transport/*.h*")                    #
LIST(APPEND T_TRANSPORT_DIR ${T_TRANSPORT_C} ${T_TRANSPORT_H})                   #
FILE(GLOB T_MAIN  "tests/main.cc")                                 #
FILE(GLOB M_RPCPROTO_C "rpcprotocol/*.c*")                         #
FILE(GLOB M_RPCPROTO_H "rpcprotocol/*.h*")                         #
LIST(APPEND M_RPCPROTO_DIR ${M_RPCPROTO_C} ${M_RPCPROTO_H})                      #
LIST(APPEND STYLE_RPCPROTO ${M_RPCPROTO_C} ${M_RPCPROTO_H})                      #
FILE(GLOB T_RPCPROTO_C "tests/rpcprotocol/*.c*")                   #
FILE(GLOB T_RPCPROTO_H "tests/rpcprotocol/*.h*")                   #
LIST(APPEND T_RPCPROTO_DIR ${T_RPCPROTO_C} ${T_RPCPROTO_H})                      #
FILE(GLOB T_UPNP_C "upnp/*.c*")                                    #
FILE(GLOB T_UPNP_H "upnp/*.h*")                                    #
LIST(APPEND T_UPNP_DIR ${T_UPNP_C} ${T_UPNP_H})                                  #
FILE(GLOB M_UPNP_C "upnp/*.c*")                                    #
FILE(GLOB M_UPNP_H "upnp/*.h*")                                    #
LIST(APPEND M_UPNP_DIR ${M_UPNP_C} ${M_UPNP_H})                                  #

######################################################################################
#All Platforms:  Add Test Exes and Create all maidsafe-dht libs                                 #
#######################################################################################
add_executable(TESTbase ${T_MAIN} ${T_BASE_DIR})
add_executable(TESTkademlia ${T_MAIN} ${T_KADEMLIA_DIR})
add_executable(TESTtransport ${T_MAIN} ${T_TRANSPORT_DIR})
add_executable(TESTrpcprotocol ${T_MAIN} ${T_RPCPROTO_DIR})
add_executable(TESTupnp ${T_MAIN} ${T_UPNP_DIR})
#######################################################################################
#Statically compile the pdlibs - then link applications/libraries to it                         #
#######################################################################################
add_library(PDbaselib STATIC ${M_BASE_DIR})
add_library(PDkademlialib STATIC ${M_KADEMLIA_DIR})
add_library(PDtransportlib STATIC ${M_TRANSPORT_DIR})
add_library(PDpbmsgslib STATIC  ${M_PROTOBUF_DIR})
add_library(PDrpcprotocollib STATIC  ${M_RPCPROTO_DIR})
add_library(PDTESTrpcprotocollib STATIC  ${M_RPCPROTO_DIR})
add_library(PDupnplib STATIC ${M_UPNP_DIR})
add_library(maidsafe-dht STATIC ${M_BASE_DIR} ${M_KADEMLIA_DIR} ${M_TRANSPORT_DIR} ${M_PROTOBUF_DIR} ${M_RPCPROTO_DIR} ${M_RPCPROTO_DIR} ${M_UPNP_DIR}  )
##########################################################################################
#Set up some extra compiler and linker flags for the tests mainly                        #
##########################################################################################
SET_TARGET_PROPERTIES(PDTESTrpcprotocollib PROPERTIES COMPILE_FLAGS " -DDEBUG -DUNIT_TEST" ) 
SET_TARGET_PROPERTIES(TESTrpcprotocol PROPERTIES COMPILE_FLAGS " -DDEBUG -DUNIT_TEST" )  
SET_TARGET_PROPERTIES(PDbaselib PROPERTIES COMPILE_FLAGS "-D__STDC_LIMIT_MACROS" )  
#########################################################################################
#BUILDS
IF (APPLE)
# Maidsafe Standard:  Boost 1_37 Library, xgcc40 compiler
	SET(SYS_LIB protobuf cryptopp sqlite3 boost_system-xgcc40-mt-1_37 boost_filesystem-xgcc40-mt-1_37 boost_regex-xgcc40-mt-1_37 boost_thread-xgcc40-mt-1_37 boost_date_time-xgcc40-mt-1_37)
ELSEIF (UNIX AND NOT APPLE)
	SET(SYS_LIB
		/usr/lib/libboost_thread-gcc43-mt.a
		sqlite3
		/usr/lib/libprotobuf.a
		/usr/lib/libboost_system-gcc43-mt.a
		/usr/lib/libboost_filesystem-gcc43-mt.a
		/usr/lib/libcryptopp.a
		/usr/lib/libboost_regex-gcc43-mt.a
		/usr/lib/libboost_date_time-gcc43-mt.a
		-lrt
		-lc
		-pthread -lgobject-2.0 -lgmodule-2.0 -lgthread-2.0 -lrt -lglib-2.0 -lSM  -ldl -lm
		)
ELSEIF (WIN32)
	IF(MSVC)
		set(SYS_LIB c:/lib/libprotobuf.lib c:/lib/cryptlib.lib c:/lib/SQLite_Static_Library.lib  c:/lib/libboost_system-vc90-mt-1_36.lib c:/lib/libboost_filesystem-vc90-mt-1_36.lib  c:/lib/libboost_regex-vc90-mt-1_36.lib  c:/lib/libboost_thread-vc90-mt-1_36.lib c:/lib/libboost_date_time-vc90-mt-1_36.lib c:/lib/WSock32.lib c:/lib/IPHlpApi.lib)
	ELSE(MSVC)
		SET(SYS_LIB
		 -ladvapi32 
		 -lkernel32 
		 -mi386pe
		-lstdc++
		-lws2_32
		c:/usr/lib/libwx_mswu-2.8.a
		c:/usr/lib/libboost_system-mgw43-mt-1_37.lib
		c:/usr/lib/libboost_filesystem-mgw43-mt-1_37.lib
		c:/usr/lib/libboost_regex-mgw43-mt-1_37.lib
		c:/usr/lib/libboost_thread-mgw43-mt-1_37.lib
		c:/usr/lib/libboost_date_time-mgw43-mt-1_37.lib
		c:/usr/lib/dokan.lib
		c:/usr/lib/libcryptopp.a
		c:/usr/lib/libprotobuf.a c:/usr/lib/libsqlite3.a -liphlpapi
		)
	ENDIF(MSVC)
ENDIF(APPLE)

TARGET_LINK_LIBRARIES(TESTbase  PDbaselib sqlite3 protobuf  gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTtransport PDtransportlib  PDbaselib PDpbmsgslib gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTrpcprotocol PDrpcprotocollib PDtransportlib  PDbaselib PDpbmsgslib gtest PDupnplib  ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTkademlia PDkademlialib PDrpcprotocollib PDtransportlib  PDbaselib PDpbmsgslib gtest PDupnplib ${SYS_LIB} )
TARGET_LINK_LIBRARIES(TESTupnp ${SYS_LIB} gtest )
TARGET_LINK_LIBRARIES(maidsafe-dht PDkademlialib PDrpcprotocollib PDtransportlib  PDbaselib PDpbmsgslib PDupnplib ${SYS_LIB} )
#TARGET_LINK_LIBRARIES(PDupnplib ${SYS_LIB})

##################################################################################
# COMPILER FLAGS  - here after all targets declared                                                                #
##################################################################################
IF (APPLE)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -D_FORTIFY_SOURCE=2 -DOSX -DBSD -D__FreeBSD__=10  -D_FILE_OFFSET_BITS=64" )
  #SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -fprofile-arcs -ftest-coverage" )
  SET(TARGET_PROPERTIES_DEBUG TESTmaidsafe TESTbase TESTkademlia TESTtransport TESTrealmaidsafe TESTrealkademlia  LINK_FLAGS -fprofile-arcs -ftest-coverage)
ELSEIF (UNIX AND NOT APPLE)
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wuninitialized")
  #SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -O0 -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra -Wall -Weffc++ -Wextra -Wfloat-equal -Wlong-long  -Wredundant-decls -Wstrict-overflow=5   -Wredundant-decls -Wunused-function  -Wunused-label  -Wunused-parameter -Wunused-value -Wunused-variable -std=c++98 -Wall -ansi -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
  ##put libs in here that will have no chance of passing tests - 3rd party ONLY !!
  SET_TARGET_PROPERTIES(PDpbmsgslib PROPERTIES COMPILE_FLAGS -w )
ELSEIF (WIN32)
IF(MSVC)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DUNICODE /D_UNICODE /D_WIN32_WINDOWS /D_CONSOLE /D__MSVC__")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} /DUNICODE /D_WIN32_WINDOWS /DDEBUG /D_CONSOLE")
ELSE(MSVC)
	#SET(CTEST_COVERAGE_COMMAND c:/MinGW/bin/gcov.exe)
  #SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -O0 -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -O0 ")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wfloat-equal -Wlong-long  -Wstrict-overflow=5 -D_FORTIFY_SOURCE=2 -fno-stack-protector  -D_FILE_OFFSET_BITS=64")
  ##put libs in here that will have no chance of passing tests - 3rd party ONLY !!
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -DWIN32_LEAN_AND_MEAN  -D__MINGW__  -L c:/MinGW/lib/ -L c:/MinGW/mingw32/lib/ -static   -mthreads -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32  -D_WIN32_WINNT=0x0501  -Ic:\\usr\\lib\\wx\\include\\msw-unicode-release-static-2.8 -I c:\\usr\\include\\wx-2.8 -D__WXMSW__ -mthreads ")
  SET_TARGET_PROPERTIES(PDpbmsgslib PROPERTIES COMPILE_FLAGS -w )
ENDIF(MSVC)
ENDIF(APPLE)
##temporarily suppress compilation warnings before warnings are taken out from upnp code
SET_TARGET_PROPERTIES(TESTupnp PDupnplib PROPERTIES COMPILE_FLAGS -w )

################################################################
# TESTS                                                        #
################################################################
INCLUDE(CTest)
SET (CTEST_CONTINUOUS_DURATION 600)
SET (CTEST_CONTINUOUS_MINIMUM_INTERVAL 10)
set(CTEST_START_WITH_EMPTY_BINARY_DIRECTORY true)
#ADD_TEST(TestIdentifier ExecutableName [Arguments])
IF(UNIX)
ADD_TEST(CHK_KAD_ ${maidsafe-dht_SOURCE_DIR}/cpplint.py ${STYLE_KADEMLIA})
ADD_TEST(CHK_BASE_ ${maidsafe-dht_SOURCE_DIR}/cpplint.py ${M_BASE_DIR})
ADD_TEST(CHK_RPC_COMPONENT ${maidsafe-dht_SOURCE_DIR}/cpplint.py ${M_RPCPROTO_DIR})
ENDIF(UNIX)
IF(UNIX)
	FOREACH(TESTTYPE TESTmaidsafe TESTfs TESTbase TESTkademlia TESTtransport TESTrpcprotocol)
ELSE(UNIX)
	FOREACH(TESTTYPE TESTmaidsafe.exe TESTbase.exe TESTkademlia.exe TESTtransport.exe  TESTrpcprotocol.exe)
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
message ("#############################################")
message("package version = " ${pddate})
message ("#############################################")
message("tests included ${MAIDSAFE_TEST_TYPE}")
message ("#############################################")
message (" you can set the test included with cmake -DMAIDSAFE_TEST_TYPE=")
message ("_ ( underscore = all) BEH (behavioural)  FUNC (functional)")
message ("#############################################")
message("Build type set to ${CMAKE_BUILD_TYPE}")
message ("#############################################")
message("You can set the build type by: cmake ../../ -DCMAKE_BUILD_TYPE=")
message("Release (default) Debug RelWithDebInfo MinSizeRel")
message ("#############################################")

IF(APPLE)
install(TARGETS maidsafe-dht
  RUNTIME
  BUNDLE DESTINATION "Perpetual Data")
ELSE(APPLE)
install(TARGETS maidsafe-dht
  ARCHIVE
  DESTINATION lib)
ENDIF(APPLE)

set(CPACK_PACKAGE_NAME "maidsafe-dht")
set(CPACK_PACKAGE_CONTACT "info@maidsafe.net")
set(CPACK_PACKAGE_VENDOR "Maidsafe.net")
 set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Perpetual Data - Client and Vault applications")
 set(CPACK_PACKAGE_INSTALL_DIRECTORY "Maidsafe")
 set(CPACK_PACKAGE_DESCRIPTION_FILE "${maidsafe-dht_SOURCE_DIR}/../docs/description.txt")
 set(CPACK_RESOURCE_FILE_LICENSE "${maidsafe-dht_SOURCE_DIR}/../docs/LICENSE.txt")
 set(CPACK_RESOURCE_FILE_README "${maidsafe-dht_SOURCE_DIR}/../docs/readme.txt")
 set(CPACK_RESOURCE_FILE_WELCOME "${maidsafe-dht_SOURCE_DIR}/../docs/welcome.txt")


IF(APPLE)

 option(CPACK_BINARY_PACKAGEMAKER "Enable to build PackageMaker packages" ON)
 #option(CPACK_BINARY_OSXX11       "Enable to build OSX X11 packages"      OFF)
 SET(CMAKE_OSX_ARCHITECTURES i386) #can add ppc;i386
 SET(MACOSX_BUNDLE_ICON_FILE "${maidsafe-dht_SOURCE_DIR}/build/install_files/maidsafe_logo_tick_ok.icns")
 SET(MACOSX_BUNDLE_GUI_IDENTIFIER "Maidsafe")
 SET(MACOSX_BUNDLE_LONG_VERSION_STRING "0.1 ALPHA")
 SET(MACOSX_BUNDLE_SHORT_VERSION_STRING "0.1")
 SET(MACOSX_BUNDLE_BUNDLE_NAME "maidsafe-dht")
 SET(MACOSX_BUNDLE_BUNDLE_VERSION "0.1")
 SET(MACOSX_BUNDLE_COPYRIGHT "Maidsafe.Net Ltd.")
 SET(GUI_TYPE MACOSX_BUNDLE)

 SET_SOURCE_FILES_PROPERTIES(
   maidsafe-dht
   PROPERTIES
   MACOSX_PACKAGE_LOCATION MACOS)

 #Copy all required icons to Resources folder
 SET_SOURCE_FILES_PROPERTIES(
   ${maidsafe-dht_SOURCE_DIR}../docs/maidsafe_logo_tick_ok.icns
   ${maidsafe-dht_SOURCE_DIR}../docs/maidsafe_logo_cross_not_ok.icns
PROPERTIES
MACOSX_PACKAGE_LOCATION Resources)

#message("-------MAC OSX Package Information------------")
#message("MACOSX_BUNDLE_ICON_FILE (must be an .icns file) is: ${MACOSX_BUNDLE_ICON_FILE}")

#message("----------------------------------------------")

ELSEIF(WIN32)
set(CPACK_GENERATOR NSIS)

SET(CPACK_NSIS_MODIFY_PATH OFF)
SET(CPACK_PACKAGE_RELOCATABLE "false")



SET(CPACK_NSIS_MUI_ICON "${maidsafe-dht_SOURCE_DIR}\\\\..\\\\docs\\\\maidsafe_logo1.ico")

#Location of the .ico icon file for the un installer in start menu
SET(CPACK_NSIS_MUI_UNIICON "${maidsafe-dht_SOURCE_DIR}\\\\..\\\\docs\\\\maidsafe_logo_cross_not_ok.ico")

#Branding image inside the installer
SET(CPACK_PACKAGE_ICON "${maidsafe-dht_SOURCE_DIR}\\\\..\\\\docs\\\\pd.png")

#setting the executable


#Setting shortcuts to maidsafe website in Programs Menu
#Can also be added links to documentation, etc
set(CPACK_NSIS_MENU_LINKS
    "http://www.maidsafe.net" "Maidsafe web site"
    "http://bug.maidsafe.net" "Maidsafe support site"
    )

SET(CPACK_RESOURCE_FILE_LICENSE "${maidsafe-dht_SOURCE_DIR}\\\\..\\\\docs\\\\EULA_001.txt")
SET(CPACK_CREATE_DESKTOP_LINKS "perpetualdata")
#NSIS installer info
SET(CPACK_NSIS_HELP_LINK "http:\\\\\\\\www.maidsafe.net")
SET(CPACK_NSIS_URL_INFO_ABOUT "http:\\\\\\\\www.maidsafe.net")
SET(CPACK_NSIS_CONTACT "contact@maidsafe.net")

ELSEIF(UNIX)
	SET(CMAKE_INSTALL_PREFIX "/usr")
  SET(CPACK_SET_DESTDIR on)

  SET(CPACK_GENERATOR DEB;RPM;TGZ)
ENDIF()
   install(FILES ${PD_SOURCE_DIR}/build/install_files/maidsafe_logo.xpm
   DESTINATION share/usr/pixmaps)
INCLUDE(CPack)
