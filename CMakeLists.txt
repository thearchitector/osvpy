cmake_minimum_required(VERSION 3.20)
project(osvpy LANGUAGES C)
find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)
find_program(GO_EXECUTABLE go REQUIRED)
find_program(GIT_EXECUTABLE git REQUIRED)
include(CheckIPOSupported)
check_ipo_supported(LANGUAGES C)

set(OSVPY_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}osvpy${CMAKE_SHARED_LIBRARY_SUFFIX}")
set(OSVPY_GO_DIR "${CMAKE_CURRENT_BINARY_DIR}/go")
# Apply pinned upstream patches in the build tree, never in the source checkout.
file(REMOVE_RECURSE "${OSVPY_GO_DIR}")
file(MAKE_DIRECTORY "${OSVPY_GO_DIR}")
file(GLOB OSVPY_GO_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/go/*.go"
  "${CMAKE_CURRENT_SOURCE_DIR}/go/go.mod"
  "${CMAKE_CURRENT_SOURCE_DIR}/go/go.sum")
foreach(source IN LISTS OSVPY_GO_SOURCES)
  get_filename_component(name "${source}" NAME)
  configure_file("${source}" "${OSVPY_GO_DIR}/${name}" COPYONLY)
endforeach()
execute_process(COMMAND "${GO_EXECUTABLE}" mod vendor
  WORKING_DIRECTORY "${OSVPY_GO_DIR}" COMMAND_ERROR_IS_FATAL ANY)
file(GLOB OSVPY_PATCHES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/go/patches/*.patch")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${OSVPY_PATCHES})
foreach(patch IN LISTS OSVPY_PATCHES)
  execute_process(COMMAND "${GIT_EXECUTABLE}" apply "${patch}"
    WORKING_DIRECTORY "${OSVPY_GO_DIR}" COMMAND_ERROR_IS_FATAL ANY)
endforeach()

add_custom_target(osvpy_native ALL
    COMMAND "${CMAKE_COMMAND}" -E env "CGO_ENABLED=1" "CC=${CMAKE_C_COMPILER}"
      "${GO_EXECUTABLE}" build -mod=vendor -trimpath -buildvcs=false
      -buildmode=c-shared -ldflags=-s -o "${OSVPY_LIBRARY}" .
    WORKING_DIRECTORY "${OSVPY_GO_DIR}"
    BYPRODUCTS "${OSVPY_LIBRARY}" "${CMAKE_CURRENT_BINARY_DIR}/libosvpy.h"
    VERBATIM)

install(FILES "${OSVPY_LIBRARY}" DESTINATION osvpy/_lib)

add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/_native.c"
  COMMAND "${Python_EXECUTABLE}" -m cython -3
    -I "${CMAKE_CURRENT_SOURCE_DIR}/src"
    -o "${CMAKE_CURRENT_BINARY_DIR}/_native.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/osvpy/_native.pyx"
  DEPENDS src/osvpy/_native.pyx src/osvpy/_abi.pxd VERBATIM)
Python_add_library(_native MODULE WITH_SOABI "${CMAKE_CURRENT_BINARY_DIR}/_native.c")
add_dependencies(_native osvpy_native)
target_include_directories(_native PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(_native PRIVATE "${OSVPY_LIBRARY}")
set_target_properties(_native PROPERTIES
  INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
  C_VISIBILITY_PRESET hidden)
if(APPLE)
  set_target_properties(_native PROPERTIES INSTALL_RPATH "@loader_path/_lib")
  add_custom_command(TARGET osvpy_native POST_BUILD
    COMMAND install_name_tool -id "@rpath/libosvpy.dylib" "${OSVPY_LIBRARY}"
    COMMAND codesign --force --sign - "${OSVPY_LIBRARY}"
    VERBATIM)
else()
  set_target_properties(_native PROPERTIES INSTALL_RPATH "$ORIGIN/_lib")
endif()
install(TARGETS _native LIBRARY DESTINATION osvpy)
