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
#                                                                              #
#  Module used to locate MysqlPP libs and headers.                             #
#                                                                              #
#  If using MSVC, finds only Mysqlpp libs which have been compiled using       #
#  dynamically-linked C runtime library (i.e. with /MD set rather than /MT)    #
#                                                                              #
#  Settable variables to aid with finding Mysqlpp are:                         #
#    MYSQLPP_LIB_DIR, MYSQLPP_INC_DIR and MYSQLPP_ROOT_DIR                     #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Mysqlpp_INCLUDE_DIR, Mysqlpp_LIBRARY_DIR, Mysqlpp_LIBRARY                 #
#                                                                              #
#  For MSVC, Mysqlpp_LIBRARY_DIR_DEBUG and Mysqlpp_LIBRARY_DEBUG are also set  #
#  and cached.                                                                 #
#                                                                              #
#==============================================================================#


UNSET(WARNING_MESSAGE)
UNSET(Mysqlpp_INCLUDE_DIR CACHE)
UNSET(Mysqlpp_LIBRARY_DIR CACHE)
UNSET(Mysqlpp_LIBRARY_DIR_DEBUG CACHE)
UNSET(Mysqlpp_LIBRARY CACHE)
UNSET(Mysqlpp_LIBRARY_DEBUG CACHE)

IF(MYSQLPP_LIB_DIR)
  SET(MYSQLPP_LIB_DIR ${MYSQLPP_LIB_DIR} CACHE PATH "Path to Mysqlpp libraries directory" FORCE)
ENDIF()
IF(MYSQLPP_INC_DIR)
  SET(MYSQLPP_INC_DIR ${MYSQLPP_INC_DIR} CACHE PATH "Path to Mysqlpp include directory" FORCE)
ENDIF()
IF(MYSQLPP_ROOT_DIR)
  SET(MYSQLPP_ROOT_DIR ${MYSQLPP_ROOT_DIR} CACHE PATH "Path to Mysqlpp root directory" FORCE)
ENDIF()

IF(MSVC)
  IF(CMAKE_CL_64)
    SET(MYSQLPP_LIBPATH_SUFFIX msvc/x64/Release)
  ELSE()
    SET(MYSQLPP_LIBPATH_SUFFIX msvc/gtest-md/Release)
  ENDIF()
ELSE()
  SET(MYSQLPP_LIBPATH_SUFFIX lib lib64)
ENDIF()

FIND_LIBRARY(Mysqlpp_LIBRARY NAMES mysqlpp PATHS ${MYSQLPP_LIB_DIR} ${MYSQLPP_ROOT_DIR} PATH_SUFFIXES ${MYSQLPP_LIBPATH_SUFFIX})
IF(MSVC)
  IF(CMAKE_CL_64)
    SET(MYSQLPP_LIBPATH_SUFFIX msvc/x64/Debug)
  ELSE()
    SET(MYSQLPP_LIBPATH_SUFFIX msvc/mysqlpp-md/Debug)
  ENDIF()
  FIND_LIBRARY(Mysqlpp_LIBRARY_DEBUG NAMES mysqlppd mysqlpp-mdd PATHS ${MYSQLPP_LIB_DIR} ${MYSQLPP_ROOT_DIR} PATH_SUFFIXES ${MYSQLPP_LIBPATH_SUFFIX})
ENDIF()

FIND_PATH(Mysqlpp_INCLUDE_DIR mysql++/mysql++.h PATHS ${MYSQLPP_INC_DIR} ${MYSQLPP_ROOT_DIR}/include)

GET_FILENAME_COMPONENT(MYSQLPP_LIBRARY_DIR ${Mysqlpp_LIBRARY} PATH)
SET(Mysqlpp_LIBRARY_DIR ${MYSQLPP_LIBRARY_DIR} CACHE PATH "Path to Mysqlpp libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(MYSQLPP_LIBRARY_DIR_DEBUG ${Mysqlpp_LIBRARY_DEBUG} PATH)
  SET(Mysqlpp_LIBRARY_DIR_DEBUG ${MYSQLPP_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Mysqlpp debug libraries directory" FORCE)
ENDIF()

IF(NOT Mysqlpp_LIBRARY)
  SET(WARNING_MESSAGE TRUE)
  MESSAGE("-- Did not find Mysql++ library")
ELSE()
  MESSAGE("-- Found Mysql++ library")
ENDIF()

IF(MSVC)
  IF(NOT Mysqlpp_LIBRARY_DEBUG)
    SET(WARNING_MESSAGE TRUE)
    MESSAGE("-- Did not find Mysql++ Debug library")
  ELSE()
    MESSAGE("-- Found Mysql++ Debug library")
  ENDIF()
ENDIF()

IF(NOT Mysqlpp_INCLUDE_DIR)
  SET(WARNING_MESSAGE TRUE)
  MESSAGE("-- Did not find Mysql++ library headers")
ENDIF()

IF(WARNING_MESSAGE)
  SET(WARNING_MESSAGE "   You can download it at http://tangentsoft.net/mysql++/\n")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}   If Mysql++ is already installed, run:\n")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}   ${ERROR_MESSAGE_CMAKE_PATH} -DMYSQLPP_LIB_DIR=<Path to mysql++ lib directory> and/or")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n   ${ERROR_MESSAGE_CMAKE_PATH} -DMYSQLPP_INC_DIR=<Path to mysql++ include directory> and/or")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n   ${ERROR_MESSAGE_CMAKE_PATH} -DMYSQLPP_ROOT_DIR=<Path to mysql++ root directory>")
  MESSAGE("${WARNING_MESSAGE}")
  SET(Mysqlpp_FOUND FALSE CACHE INTERNAL "Found Mysql++ library and headers" FORCE)
  UNSET(Mysqlpp_INCLUDE_DIR CACHE)
  UNSET(Mysqlpp_LIBRARY_DIR CACHE)
  UNSET(Mysqlpp_LIBRARY_DIR_DEBUG CACHE)
  UNSET(Mysqlpp_LIBRARY CACHE)
  UNSET(Mysqlpp_LIBRARY_DEBUG CACHE)
ELSE()
  SET(Mysqlpp_FOUND TRUE CACHE INTERNAL "Found Mysql++ library and headers" FORCE)
ENDIF()
