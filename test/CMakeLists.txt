cmake_minimum_required (VERSION 2.6)

PROJECT(fctparse C)

SET(EXE_NAME fctparse)

SET(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -fpermissive )
SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -fpermissive )

add_definitions(-DUSB_SEGMENT_SIZE=128 -DIO_HID_EP_LENGTH=128)
INCLUDE_DIRECTORIES("${PROJECT_BINARY_DIR}"
                    ../src/
                    $ENV{BOLOS_SDK}/include
)

SET(CONVERT_LIBS 
      crypto
      stdc++
   )              


ADD_EXECUTABLE(${EXE_NAME}
    main.c
    surrogate.c
    ../src/fatParse.c
    ../src/fctParse.h
    ../src/fctParse.c
    ../src/ecParse.h
    ../src/ecParse.c
    ../src/ccParse.h
    ../src/ccParse.c
    ../src/fctUtils.h
    ../src/fctUtils.c
    ../src/btchip_base58.h
    ../src/btchip_base58.c
    ../src/btchip_rom_variables.h
    ../src/btchip_rom_variables.c
    ../src/btchip_apdu_constants.h)

SET_TARGET_PROPERTIES(${EXE_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

TARGET_LINK_LIBRARIES(${EXE_NAME} ${CONVERT_LIBS})

IF(UNIX)

#add_custom_command(TARGET ${EXE_NAME} PRE_BUILD COMMAND  
#                   mkdir -p {CMAKE_SOURCE_DIR}/bin VERBATIM)

#add_custom_command(TARGET ${EXE_NAME} PRE_BUILD COMMAND  
#                   ln -sf ${CMAKE_BINARY_DIR}/bin/${EXE_NAME}
#                   ${CMAKE_SOURCE_DIR}/bin/${EXE_NAME} VERBATIM)

ENDIF(UNIX)
