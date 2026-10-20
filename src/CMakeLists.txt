# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

pkg_check_modules(JSON REQUIRED "jsoncpp")
pkg_check_modules(SASL REQUIRED "libsasl2")

include_directories(${CMAKE_SOURCE_DIR}/src)

set(SOURCES
  client.cc
  client.h
  client_assertion.cc
  client_assertion.h
  config.cc
  config.h
  http.cc
  http.h
  log.cc
  log.h
  module.cc
  module.h
  token_store.cc
  token_store.h)

set(TEST_CONFIG_SOURCES
  test_config.cc)

set(CONFIG_FILE ${PROJECT_NAME}.conf)
set(CONFIG_FILE_FULL_PATH ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${CONFIG_FILE})

link_directories(${JSON_LIBRARY_DIRS})

# The plugin runs inside the mail agent's delivery processes: build it (and
# its helpers) with the usual hardening. _FORTIFY_SOURCE needs optimization,
# so it is only added for optimized builds (glibc warns otherwise, and warnings
# are errors here).
set(HARDENING_COMPILE_OPTIONS -fstack-protector-strong -D_GLIBCXX_ASSERTIONS)
if(CMAKE_BUILD_TYPE MATCHES "^(Release|RelWithDebInfo|MinSizeRel)$")
  list(APPEND HARDENING_COMPILE_OPTIONS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
endif()
set(HARDENING_LINK_OPTIONS -Wl,-z,relro -Wl,-z,now)

function(sasl_xoauth2_target_setup target)
  target_compile_options(${target} PRIVATE -Wall -Werror ${HARDENING_COMPILE_OPTIONS})
  target_link_options(${target} PRIVATE ${HARDENING_LINK_OPTIONS})
  target_include_directories(${target} SYSTEM PUBLIC ${CURL_INCLUDE_DIRS} ${SASL_INCLUDE_DIRS} ${JSON_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
  target_compile_definitions(${target} PRIVATE
    CONFIG_FILE_FULL_PATH="${CONFIG_FILE_FULL_PATH}"
    SASL_XOAUTH2_VERSION="${PROJECT_VERSION}")
endfunction()

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${CONFIG_FILE})
sasl_xoauth2_target_setup(${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME} ${CURL_LIBRARIES} ${JSON_LIBRARIES} OpenSSL::Crypto)
# Export only sasl_client_plug_init (see module.cc), not the internals.
set_target_properties(${PROJECT_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON)

add_library(${PROJECT_NAME}-static STATIC ${SOURCES} ${CONFIG_FILE})
sasl_xoauth2_target_setup(${PROJECT_NAME}-static)
target_link_libraries(${PROJECT_NAME}-static ${CURL_LIBRARIES} ${JSON_LIBRARIES} OpenSSL::Crypto)

add_executable(test-config ${TEST_CONFIG_SOURCES} ${CONFIG_FILE})
sasl_xoauth2_target_setup(test-config)
target_link_libraries(test-config ${PROJECT_NAME}-static ${CURL_LIBRARIES} ${JSON_LIBRARIES} OpenSSL::Crypto)

install(
  TARGETS ${PROJECT_NAME}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/sasl2)

install(
  TARGETS test-config
  RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME})

# The configuration holds the client ID (and possibly the client secret): only
# install the template if there is no configuration yet, never overwrite one,
# and do not make it world-readable (0640; see the README for its group).
install(
  CODE "
    set(config_path \"\$ENV{DESTDIR}${CONFIG_FILE_FULL_PATH}\")
    if(EXISTS \"\${config_path}\")
      message(STATUS \"Keeping existing: \${config_path}\")
    else()
      file(INSTALL
        DESTINATION \"${CMAKE_INSTALL_FULL_SYSCONFDIR}\"
        TYPE FILE
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ
        FILES \"${CMAKE_CURRENT_SOURCE_DIR}/${CONFIG_FILE}\")
    endif()"
  COMPONENT config)

if(EnableTests)
  add_executable(${PROJECT_NAME}_test xoauth2_test.cc)
  sasl_xoauth2_target_setup(${PROJECT_NAME}_test)
  # The static library: the shared one exports nothing but the plugin entry.
  target_link_libraries(${PROJECT_NAME}_test ${PROJECT_NAME}-static ${CURL_LIBRARIES} ${JSON_LIBRARIES} OpenSSL::Crypto)

  add_test(
    NAME ${PROJECT_NAME}_test
    COMMAND ${PROJECT_NAME}_test)
endif()
