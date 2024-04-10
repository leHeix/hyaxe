cmake_minimum_required (VERSION 3.12)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("hyaxe")

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_definitions(
	HAVE_STDINT_H
	$<$<PLATFORM_ID:Linux>:LINUX>
)
add_subdirectory(lib)

file(GLOB_RECURSE HYAXE_SRC_FILES
	"src/*.hpp"
	"src/*.cpp"
)

add_library(hyaxe SHARED "src/exports.def" ${HYAXE_SRC_FILES})
target_compile_features(hyaxe PRIVATE cxx_std_20 c_std_11)
target_link_libraries(hyaxe PRIVATE SAMPGDK)
target_include_directories(hyaxe PRIVATE ./lib)
