cmake_minimum_required(VERSION 3.20)
project(osvpy LANGUAGES C)
find_program(GO_EXECUTABLE go REQUIRED)

if(APPLE)
  set(OSVPY_LIBRARY libosvpy.dylib)
else()
  set(OSVPY_LIBRARY libosvpy.so)
endif()

set(OSVPY_NATIVE_DIR "${CMAKE_CURRENT_BINARY_DIR}/native")
file(MAKE_DIRECTORY "${OSVPY_NATIVE_DIR}")

add_custom_target(osvpy_native ALL
    COMMAND "${CMAKE_COMMAND}" -E env "CGO_ENABLED=1" "CC=${CMAKE_C_COMPILER}"
      "${GO_EXECUTABLE}" build -mod=readonly -trimpath -buildvcs=false
      -buildmode=c-shared "-ldflags=-s -w" -o "${OSVPY_NATIVE_DIR}/${OSVPY_LIBRARY}" .
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/go"
    BYPRODUCTS "${OSVPY_NATIVE_DIR}/${OSVPY_LIBRARY}"
    VERBATIM)

install(FILES "${OSVPY_NATIVE_DIR}/${OSVPY_LIBRARY}" DESTINATION osvpy/_lib)
