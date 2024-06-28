# Author: Nikolai Vorontsov
# Copyright (c) 2024 VorontSOFT
cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)

project(HyperVTool VERSION 0.1.0.0 LANGUAGES CXX)

file(GLOB HVT_SOURCES *.cpp)
add_executable(${PROJECT_NAME} ${HVT_SOURCES})

if(WIN32)
  target_sources(${PROJECT_NAME} PRIVATE HyperVTool.rc)
  if(${STATIC_RUNTIME})
    set_property(TARGET ${PROJECT_NAME} PROPERTY
                 MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()	
  # force Unicode over Multi-byte
  add_definitions(-DUNICODE -D_UNICODE)
else()
  error("Only Windows is supported")
endif()
