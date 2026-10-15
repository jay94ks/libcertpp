if(NOT DEFINED SOURCE_DIR OR NOT DEFINED BINARY_DIR)
    message(FATAL_ERROR "SOURCE_DIR and BINARY_DIR are required")
endif()

set(prefix "${BINARY_DIR}/consumer-prefix")
set(consumer_binary "${BINARY_DIR}/consumer-build")
file(REMOVE_RECURSE "${prefix}" "${consumer_binary}")

set(config_args)
if(DEFINED CONFIG AND NOT CONFIG STREQUAL "")
    list(APPEND config_args --config "${CONFIG}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${BINARY_DIR}" ${config_args} --prefix "${prefix}"
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "certpp installation failed: ${result}")
endif()

set(generator_args)
if(DEFINED GENERATOR AND NOT GENERATOR STREQUAL "")
    list(APPEND generator_args -G "${GENERATOR}")
endif()
if(DEFINED GENERATOR_PLATFORM AND NOT GENERATOR_PLATFORM STREQUAL "")
    list(APPEND generator_args -A "${GENERATOR_PLATFORM}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}/cmake/consumer" -B "${consumer_binary}"
            ${generator_args} "-DCMAKE_PREFIX_PATH=${prefix}"
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "consumer configuration failed: ${result}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${consumer_binary}" ${config_args}
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "consumer build failed: ${result}")
endif()

set(executable "${consumer_binary}/certpp_consumer${EXECUTABLE_SUFFIX}")
if(DEFINED CONFIG AND NOT CONFIG STREQUAL "" AND EXISTS "${consumer_binary}/${CONFIG}/certpp_consumer${EXECUTABLE_SUFFIX}")
    set(executable "${consumer_binary}/${CONFIG}/certpp_consumer${EXECUTABLE_SUFFIX}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "PATH=${prefix}/bin;$ENV{PATH}" "${executable}"
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "consumer execution failed: ${result}")
endif()
