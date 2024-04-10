add_library(SAMPGDK STATIC "sampgdk.h" "sampgdk.c")
target_compile_definitions(SAMPGDK PUBLIC 
	SAMPGDK_STATIC=1
	SAMPGDK_AMALGAMATION=1
)
target_include_directories(SAMPGDK PUBLIC "../samp-sdk")
target_link_libraries(SAMPGDK PUBLIC SAMPSDK)