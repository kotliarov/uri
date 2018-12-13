cmake_minimum_required(VERSION 3.10)
set (CMAKE_CXX_STANDARD 11)

find_package(Boost COMPONENTS unit_test_framework REQUIRED)
message(status "** Boost Include: ${Boost_INCLUDE_DIR}")
message(status "** Boost Libraries: ${Boost_LIBRARY_DIRS}")
message(status "** Boost Libraries: ${Boost_LIBRARIES}")

include_directories(${Boost_INCLUDE_DIRS} include)

enable_testing()

file(GLOB TEST_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} test/*.cpp)
foreach(test_src ${TEST_SRC})
        # Set test_name to basename of the source file.
        get_filename_component(test_name ${test_src} NAME_WE)

        add_executable(
        	${test_name} ${test_src}
        )
        #link to Boost libraries AND your targets and dependencies
        target_link_libraries(
        	${test_name}
        	${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}
        )

        # Move testing binaries into a ./bin directory
        set_target_properties(${test_name} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/bin)

        #Finally add it to test execution -
        #Notice the WORKING_DIRECTORY and COMMAND
        add_test(NAME ${test_name}
                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
                 COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/bin/${test_name} )
endforeach(test_src)