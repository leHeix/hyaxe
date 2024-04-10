add_library(SAMPSDK STATIC
	"amxplugin.cpp"
	"amxplugin2.cpp"
)

if(UNIX)
	target_sources(SAMPSDK PUBLIC "amx/getch.c")
endif()