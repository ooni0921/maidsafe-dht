# Install script for directory: /Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src

# Set the install prefix
IF(NOT DEFINED CMAKE_INSTALL_PREFIX)
  SET(CMAKE_INSTALL_PREFIX "/usr")
ENDIF(NOT DEFINED CMAKE_INSTALL_PREFIX)
STRING(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
IF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  IF(BUILD_TYPE)
    STRING(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  ELSE(BUILD_TYPE)
    SET(CMAKE_INSTALL_CONFIG_NAME "Release")
  ENDIF(BUILD_TYPE)
  MESSAGE(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
ENDIF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)

# Set the component getting installed.
IF(NOT CMAKE_INSTALL_COMPONENT)
  IF(COMPONENT)
    MESSAGE(STATUS "Install component: \"${COMPONENT}\"")
    SET(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  ELSE(COMPONENT)
    SET(CMAKE_INSTALL_COMPONENT)
  ENDIF(COMPONENT)
ENDIF(NOT CMAKE_INSTALL_COMPONENT)

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  FILE(INSTALL DESTINATION "/usr/include/maidsafe" TYPE FILE FILES
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/maidsafe-dht.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/maidsafe-dht_config.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/utils.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/crypto.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/routingtable.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/alternativestore.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/protobuf/signed_kadvalue.pb.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/protobuf/kademlia_service_messages.pb.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/protobuf/contact_info.pb.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/protobuf/general_messages.pb.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/online.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/config.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/transport-api.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/channel-api.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/channelmanager-api.h"
    "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/maidsafe/knode-api.h"
    )
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  FILE(INSTALL DESTINATION "/usr/lib" TYPE STATIC_LIBRARY FILES "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/build/OSX/Release/lib/libmaidsafe-dht.a")
  IF(EXISTS "$ENV{DESTDIR}/usr/lib/libmaidsafe-dht.a")
    EXECUTE_PROCESS(COMMAND "/usr/bin/ranlib" "$ENV{DESTDIR}/usr/lib/libmaidsafe-dht.a")
  ENDIF(EXISTS "$ENV{DESTDIR}/usr/lib/libmaidsafe-dht.a")
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

IF(CMAKE_INSTALL_COMPONENT)
  SET(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
ELSE(CMAKE_INSTALL_COMPONENT)
  SET(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
ENDIF(CMAKE_INSTALL_COMPONENT)

FILE(WRITE "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/build/OSX/${CMAKE_INSTALL_MANIFEST}" "")
FOREACH(file ${CMAKE_INSTALL_MANIFEST_FILES})
  FILE(APPEND "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/build/OSX/${CMAKE_INSTALL_MANIFEST}" "${file}\n")
ENDFOREACH(file)
