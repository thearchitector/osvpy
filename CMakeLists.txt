cmake_minimum_required(VERSION 3.20)
project(pyosv LANGUAGES NONE)

if(APPLE)
  set(PYOSV_LIBRARY libpyosv.dylib)
else()
  set(PYOSV_LIBRARY libpyosv.so)
endif()

set(PYOSV_NATIVE_DIR "${CMAKE_CURRENT_BINARY_DIR}/native")
file(MAKE_DIRECTORY "${PYOSV_NATIVE_DIR}")

if(DEFINED ENV{PYOSV_PREBUILT_LIBRARY})
  set(PYOSV_PREBUILT "$ENV{PYOSV_PREBUILT_LIBRARY}")
  configure_file("${PYOSV_PREBUILT}" "${PYOSV_NATIVE_DIR}/${PYOSV_LIBRARY}" COPYONLY)
else()
  enable_language(C)
  find_program(GO_EXECUTABLE go REQUIRED)
  add_custom_target(pyosv_native ALL
    COMMAND "${CMAKE_COMMAND}" -E env "CGO_ENABLED=1" "CC=${CMAKE_C_COMPILER}"
      "${GO_EXECUTABLE}" build -mod=readonly -trimpath -buildvcs=false
      -buildmode=c-shared "-ldflags=-s -w" -o "${PYOSV_NATIVE_DIR}/${PYOSV_LIBRARY}" .
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/go"
    BYPRODUCTS "${PYOSV_NATIVE_DIR}/${PYOSV_LIBRARY}"
    VERBATIM)
endif()

install(FILES "${PYOSV_NATIVE_DIR}/${PYOSV_LIBRARY}" DESTINATION pyosv/_lib)
