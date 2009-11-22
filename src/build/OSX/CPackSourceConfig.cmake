# This file will be configured to contain variables for CPack. These variables
# should be set in the CMake list file of the project before CPack module is
# included. Example variables are:
#   CPACK_GENERATOR                     - Generator used to create package
#   CPACK_INSTALL_CMAKE_PROJECTS        - For each project (path, name, component)
#   CPACK_CMAKE_GENERATOR               - CMake Generator used for the projects
#   CPACK_INSTALL_COMMANDS              - Extra commands to install components
#   CPACK_INSTALL_DIRECTORIES           - Extra directories to install
#   CPACK_PACKAGE_DESCRIPTION_FILE      - Description file for the package
#   CPACK_PACKAGE_DESCRIPTION_SUMMARY   - Summary of the package
#   CPACK_PACKAGE_EXECUTABLES           - List of pairs of executables and labels
#   CPACK_PACKAGE_FILE_NAME             - Name of the package generated
#   CPACK_PACKAGE_ICON                  - Icon used for the package
#   CPACK_PACKAGE_INSTALL_DIRECTORY     - Name of directory for the installer
#   CPACK_PACKAGE_NAME                  - Package project name
#   CPACK_PACKAGE_VENDOR                - Package project vendor
#   CPACK_PACKAGE_VERSION               - Package project version
#   CPACK_PACKAGE_VERSION_MAJOR         - Package project version (major)
#   CPACK_PACKAGE_VERSION_MINOR         - Package project version (minor)
#   CPACK_PACKAGE_VERSION_PATCH         - Package project version (patch)

# There are certain generator specific ones

# NSIS Generator:
#   CPACK_PACKAGE_INSTALL_REGISTRY_KEY  - Name of the registry key for the installer
#   CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS - Extra commands used during uninstall
#   CPACK_NSIS_EXTRA_INSTALL_COMMANDS   - Extra commands used during install


SET(CPACK_BINARY_BUNDLE "")
SET(CPACK_BINARY_CYGWIN "")
SET(CPACK_BINARY_DEB "")
SET(CPACK_BINARY_DRAGNDROP "")
SET(CPACK_BINARY_NSIS "")
SET(CPACK_BINARY_OSXX11 "")
SET(CPACK_BINARY_PACKAGEMAKER "")
SET(CPACK_BINARY_RPM "")
SET(CPACK_BINARY_STGZ "")
SET(CPACK_BINARY_TBZ2 "")
SET(CPACK_BINARY_TGZ "")
SET(CPACK_BINARY_TZ "")
SET(CPACK_BINARY_ZIP "")
SET(CPACK_CMAKE_GENERATOR "Unix Makefiles")
SET(CPACK_COMPONENT_UNSPECIFIED_HIDDEN "TRUE")
SET(CPACK_COMPONENT_UNSPECIFIED_REQUIRED "TRUE")
SET(CPACK_GENERATOR "TGZ;TBZ2;TZ")
SET(CPACK_IGNORE_FILES "/CVS/;/\\.svn/;\\.swp$;\\.#;/#")
SET(CPACK_INSTALLED_DIRECTORIES "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src;/")
SET(CPACK_INSTALL_CMAKE_PROJECTS "")
SET(CPACK_INSTALL_PREFIX "/usr")
SET(CPACK_MODULE_PATH "")
SET(CPACK_NSIS_DISPLAY_NAME "Maidsafe")
SET(CPACK_NSIS_INSTALLER_ICON_CODE "")
SET(CPACK_NSIS_INSTALLER_MUI_ICON_CODE "")
SET(CPACK_NSIS_PACKAGE_NAME "Maidsafe")
SET(CPACK_OUTPUT_CONFIG_FILE "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/build/OSX/CPackConfig.cmake")
SET(CPACK_PACKAGE_CONTACT "info@maidsafe.net")
SET(CPACK_PACKAGE_DEFAULT_LOCATION "/")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/../docs/description.txt")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Perpetual Data - Client and Vault applications")
SET(CPACK_PACKAGE_FILE_NAME "maidsafe-dht-0.1.Sun221109-Source")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "Maidsafe")
SET(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "maidsafe-dht 0.1.Sun221109")
SET(CPACK_PACKAGE_NAME "maidsafe-dht")
SET(CPACK_PACKAGE_RELOCATABLE "true")
SET(CPACK_PACKAGE_VENDOR "Maidsafe.net")
SET(CPACK_PACKAGE_VERSION "0.1.Sun221109")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "1")
SET(CPACK_PACKAGE_VERSION_PATCH "Sun221109")
SET(CPACK_RESOURCE_FILE_LICENSE "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/../docs/LICENSE.txt")
SET(CPACK_RESOURCE_FILE_README "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/../docs/readme.txt")
SET(CPACK_RESOURCE_FILE_WELCOME "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/../docs/welcome.txt")
SET(CPACK_SET_DESTDIR "on")
SET(CPACK_SOURCE_CYGWIN "")
SET(CPACK_SOURCE_GENERATOR "TGZ;TBZ2;TZ")
SET(CPACK_SOURCE_IGNORE_FILES "/CVS/;/\\.svn/;\\.swp$;\\.#;/#")
SET(CPACK_SOURCE_INSTALLED_DIRECTORIES "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src;/")
SET(CPACK_SOURCE_OUTPUT_CONFIG_FILE "/Users/julian/Documents/Development/maidsafe/branches/b-jc-nat-pmp/src/build/OSX/CPackSourceConfig.cmake")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "maidsafe-dht-0.1.Sun221109-Source")
SET(CPACK_SOURCE_TBZ2 "ON")
SET(CPACK_SOURCE_TGZ "ON")
SET(CPACK_SOURCE_TOPLEVEL_TAG "Darwin-Source")
SET(CPACK_SOURCE_TZ "ON")
SET(CPACK_SOURCE_ZIP "OFF")
SET(CPACK_STRIP_FILES "")
SET(CPACK_SYSTEM_NAME "Darwin")
SET(CPACK_TOPLEVEL_TAG "Darwin-Source")
