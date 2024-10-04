cmake_minimum_required(VERSION 3.10)
project(quickjs-browser-env)

# Set the CMake variables
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

# Include the FetchContent module
include(FetchContent)

# =================================================================================================
# Download and build Quickjs NG
# =================================================================================================
# FetchContent_Declare(
#   quickjs
#   GIT_REPOSITORY https://github.com/quickjs-ng/quickjs.git
#   GIT_TAG v0.6.1
# )

# set(BUILD_QJS_LIBC ON CACHE INTERNAL "" FORCE)
# FetchContent_MakeAvailable(quickjs)


# Download and build quickjs
FetchContent_Declare(
  quickjs
  GIT_REPOSITORY https://github.com/bellard/quickjs.git
  GIT_TAG master
)

# Make sure quickjs will be populated and built
FetchContent_MakeAvailable(quickjs)


# Change to the quickjs source directory
# add_custom_command(TARGET quickjs POST_BUILD
#   COMMAND ${CMAKE_COMMAND} -E chdir ${quickjs_SOURCE_DIR} make
# )

add_custom_target(
   quickjs_lib
   COMMAND make
   WORKING_DIRECTORY ${quickjs_SOURCE_DIR}
  )


# =================================================================================================
# Download and build CivetWeb
# =================================================================================================
FetchContent_Declare(
  civetweb
  GIT_REPOSITORY https://github.com/civetweb/civetweb.git
  GIT_TAG v1.16

)

set(CIVETWEB_BUILD_TESTING OFF CACHE INTERNAL "" FORCE)
set(CIVETWEB_ENABLE_SERVER_EXECUTABLE OFF CACHE INTERNAL "" FORCE)
set(CIVETWEB_ENABLE_CXX ON CACHE INTERNAL "" FORCE)
set(CIVETWEB_ENABLE_WEBSOCKETS ON CACHE INTERNAL "" FORCE)
set(CIVETWEB_ENABLE_ASAN OFF CACHE INTERNAL "" FORCE)

# add_subdirectory(civetweb)

FetchContent_MakeAvailable(civetweb)


# =================================================================================================
# Target
# =================================================================================================
# Now you can use quickjs in your project
add_executable(${PROJECT_NAME} main.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE ${quickjs_SOURCE_DIR} ${civetweb_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} PRIVATE quickjs civetweb-cpp) #
target_link_directories(${PROJECT_NAME} PRIVATE ${quickjs_SOURCE_DIR})
add_dependencies(${PROJECT_NAME} quickjs_lib )
