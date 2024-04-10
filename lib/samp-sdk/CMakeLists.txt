add_library(SAMPSDK STATIC
	"amxplugin.cpp"
	"amxplugin2.cpp"
	"amx/amx.h"
)

if(UNIX)
	target_sources(SAMPSDK PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/amx/getch.c" "${CMAKE_CURRENT_SOURCE_DIR}/amx/sclinux.h")
endif()