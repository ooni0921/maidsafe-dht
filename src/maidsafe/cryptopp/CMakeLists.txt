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


SET_DIRECTORY_PROPERTIES(PROPERTIES INCLUDE_DIRECTORIES "")

FILE(GLOB cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
IF(MSVC)
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/eprecomp.cpp")
ENDIF()
FILE(GLOB cryptopp_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/*.h")

#ADD_LIBRARY(cryptopp SHARED ${cryptopp_SOURCES} ${cryptopp_HEADERS})
ADD_LIBRARY(cryptopp_static STATIC ${cryptopp_SOURCES} ${cryptopp_HEADERS})
#IF(NOT MSVC)
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES OUTPUT_NAME cryptopp)
#ENDIF()

IF(MSVC)
  INSTALL(TARGETS cryptopp_static # cryptopp
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION bin
            ARCHIVE DESTINATION lib
          )

ELSE()
  INSTALL(TARGETS cryptopp_static # cryptopp
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
          )
ENDIF()

IF(NOT MSVC)
  ADD_DEFINITIONS(-DNDEBUG)
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET(OPT_FLAG "-O3")
ELSE()
  SET(OPT_FLAG "")
ENDIF()
IF(APPLE)
  ADD_DEFINITIONS(-DCRYPTOPP_DISABLE_ASM)
#  SET_TARGET_PROPERTIES(cryptopp PROPERTIES COMPILE_FLAGS "-w -finline-functions ${OPT_FLAG}")
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES COMPILE_FLAGS "-fPIC -w -finline-functions ${OPT_FLAG}")
ELSEIF(UNIX AND NOT APPLE)
#  SET_TARGET_PROPERTIES(cryptopp PROPERTIES COMPILE_FLAGS "-w -pipe -finline-functions ${OPT_FLAG}")
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES COMPILE_FLAGS "-fPIC -w -pipe -finline-functions ${OPT_FLAG}")
ELSEIF(WIN32 AND NOT MSVC)
#  SET_TARGET_PROPERTIES(cryptopp PROPERTIES COMPILE_FLAGS "-mthreads -w -finline-functions ${OPT_FLAG} -D_WIN32_WINNT=0x0501")
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES COMPILE_FLAGS "-mthreads -w -finline-functions ${OPT_FLAG} -D_WIN32_WINNT=0x0501")
ELSEIF(WIN32 AND MSVC)
  CMAKE_POLICY(SET CMP0008 NEW)
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES COMPILE_FLAGS "/D_WINDOWS /DUSE_PRECOMPILED_HEADERS /DWIN32 /D_VC80_UPGRADE=0x0710 /EHsc /W3")
  SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Oi /Oy /GL /DNDEBUG /GF /MD /Gy /Zi")
  SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Oi /D_DEBUG /MDd /arch:SSE /ZI")
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/adhoc.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/bench.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/bench2.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_bds.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/datatest.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/dll.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/dlltest.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/fipsalgt.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/iterhash.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/regtest.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/test.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/pch.cpp") # this file is used to create precompiled headers
  SET_SOURCE_FILES_PROPERTIES(${cryptopp_SOURCES} PROPERTIES
                               COMPILE_FLAGS "/Yu\"pch.h\"")
  SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_SOURCE_DIR}/pch.cpp PROPERTIES
                               COMPILE_FLAGS "/Yc\"pch.h\"")
ENDIF()
