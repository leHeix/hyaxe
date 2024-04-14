
set(BOTAN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/$<IF:$<CONFIG:Debug>,debug,release>/$<IF:$<PLATFORM_ID:Windows>,win,linux>)

add_library(Botan STATIC
	"${BOTAN_DIR}/src/botan_all.cpp"
)

target_compile_features(Botan PRIVATE cxx_std_20)
target_compile_definitions(Botan PRIVATE
	BOTAN_DLL=
	_REENTRANT=
)
target_link_libraries(Botan PRIVATE Threads::Threads)

if(MSVC)
	target_compile_options(Botan PRIVATE /EHs /GR /bigobj /FS /Oi /Zc:throwingNew)
else()
	target_compile_options(Botan PRIVATE -fstack-protector)
endif()