cmake_minimum_required (VERSION 2.8)

if(WIN32)
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
    foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /FD /EHsc /W3 /TP")
    set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} /FD /EHsc /W3 /TP")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fstack-protector-all")
endif()

if (IOS)
    if (NOT CMAKE_GENERATOR STREQUAL "Xcode")
        message(FATAL_ERROR "only xcode generator is supported for iOS")
    endif ()

    set(CMAKE_XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "8.0")
    if (IOS STREQUAL "sim")
        set(CMAKE_OSX_SYSROOT iphonesimulator)
    else ()
        set(CMAKE_OSX_SYSROOT iphoneos)
    endif ()
    set(CMAKE_OSX_ARCHITECTURES "$(ARCHS_STANDARD_INCLUDING_64_BIT)")
    set(CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR})
    SET(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphoneos;-iphonesimulator" )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mios-version-min=8.0")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mios-version-min=8.0")
    add_definitions(-DIOS)
elseif (APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mmacosx-version-min=10.9")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mmacosx-version-min=10.9")
endif (IOS)
