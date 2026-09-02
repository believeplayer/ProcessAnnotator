cmake_minimum_required(VERSION 3.20)
project(ProcessAnnotator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(MSVC)
    add_compile_options(/utf-8 /Zc:__cplusplus /permissive-)
    add_compile_definitions(UNICODE _UNICODE)
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

include(FetchContent)
FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG        0.8.0
    GIT_SHALLOW    TRUE
)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yaml-cpp)

set(PA_SOURCES
    src/main.cpp
    src/core/Privilege.cpp
    src/core/ProcessCollector.cpp
    src/core/ProcessTree.cpp
    src/core/RuleEngine.cpp
    src/core/Signature.cpp
    src/core/ModuleEnumerator.cpp
    src/core/SnapshotDiff.cpp
    src/core/ProcessExtras.cpp
    src/core/FileHash.cpp
    src/core/AutostartIndex.cpp
    src/i18n/I18n.cpp
    src/vt/VirusTotal.cpp
    src/ui/MainWindow.cpp
    src/ui/ProcessView.cpp
    src/ui/ReportBuilder.cpp
    src/ui/RefreshWorker.cpp
    resources/resources.qrc
    src/ui/MainWindow.hpp
    src/ui/RefreshWorker.hpp
)

foreach(src IN LISTS PA_SOURCES)
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${src}")
        message(FATAL_ERROR "Missing source: ${src}\nCopy the full project tree (including src/ui/ProcessView.cpp, ReportBuilder.cpp, RefreshWorker.cpp).")
    endif()
endforeach()

add_executable(ProcessAnnotator WIN32 ${PA_SOURCES})

target_include_directories(ProcessAnnotator PRIVATE src)
target_link_libraries(ProcessAnnotator PRIVATE
    Qt6::Widgets
    Qt6::Network
    yaml-cpp
)

if(WIN32)
    target_sources(ProcessAnnotator PRIVATE resources/app.rc)
    target_link_libraries(ProcessAnnotator PRIVATE ntdll wintrust crypt32)
endif()

add_custom_command(TARGET ProcessAnnotator POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:ProcessAnnotator>/rules
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/rules/rules.yaml
        $<TARGET_FILE_DIR:ProcessAnnotator>/rules/rules.yaml
)

add_custom_command(TARGET ProcessAnnotator POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:ProcessAnnotator>/rules/rules.d"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/rules/rules.d"
        "$<TARGET_FILE_DIR:ProcessAnnotator>/rules/rules.d"
)
