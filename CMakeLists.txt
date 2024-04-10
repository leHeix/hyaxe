cmake_minimum_required (VERSION 3.21)

project ("hyaxe")

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(VCPKG_TARGET_ARCHITECTURE x86)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CRT_LINKAGE static)
find_package(fmt CONFIG REQUIRED)

add_compile_definitions(
	HAVE_STDINT_H
	$<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN>
	$<$<PLATFORM_ID:Linux>:LINUX>
)
add_subdirectory(lib)

file(GLOB_RECURSE HYAXE_SRC_FILES
	"src/*.hpp"
	"src/*.cpp"
)

add_library(hyaxe SHARED "src/exports.def" ${HYAXE_SRC_FILES})
target_compile_features(hyaxe PRIVATE cxx_std_20 c_std_11)
target_link_libraries(hyaxe PRIVATE SAMPGDK fmt::fmt)
target_include_directories(hyaxe PRIVATE ./lib)
set_target_properties(hyaxe PROPERTIES
	UNITY_BUILD ON
	UNITY_BUILD_BATCH_SIZE 15
	PREFIX ""
	LIBRARY_OUTPUT_DIRECTORY  "${CMAKE_CURRENT_SOURCE_DIR}/server/plugins"
	RUNTIME_OUTPUT_DIRECTORY  "${CMAKE_CURRENT_SOURCE_DIR}/server/plugins"
)
target_precompile_headers(hyaxe PUBLIC "src/pch.h")