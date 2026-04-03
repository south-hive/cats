cmake_minimum_required(VERSION 3.20)

project(libsed
    VERSION 0.1.0
    DESCRIPTION "TCG SED Self-Encrypting Drive C++ Library"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ══════════════════════════════════════════════════════
#  Options
# ══════════════════════════════════════════════════════
option(LIBSED_BUILD_TESTS    "Build unit tests"      ON)
option(LIBSED_BUILD_EXAMPLES "Build example programs" ON)
option(LIBSED_BUILD_TOOLS    "Build CLI tools"        ON)
option(LIBSED_BUILD_SHARED   "Build shared library"   OFF)

# ══════════════════════════════════════════════════════
#  Source files
# ══════════════════════════════════════════════════════
set(LIBSED_SOURCES
    # Core
    src/sed_library.cpp
    src/sed_device.cpp

    # Codec
    src/codec/token.cpp
    src/codec/token_encoder.cpp
    src/codec/token_decoder.cpp
    src/codec/token_stream.cpp
    src/codec/token_list.cpp

    # Packet
    src/packet/com_packet.cpp
    src/packet/packet_builder.cpp

    # Method
    src/method/method_call.cpp
    src/method/method_result.cpp
    src/method/param_encoder.cpp
    src/method/param_decoder.cpp

    # Session
    src/session/session.cpp
    src/session/session_manager.cpp
    src/session/trusted_peripheral.cpp
    src/session/com_id_manager.cpp

    # Transport
    src/transport/ata_transport.cpp
    src/transport/nvme_transport.cpp
    src/transport/scsi_transport.cpp
    src/transport/transport_factory.cpp

    # Discovery
    src/discovery/discovery.cpp
    src/discovery/feature_descriptor.cpp

    # Table
    src/table/table_ops.cpp
    src/table/row.cpp
    src/table/acl_ops.cpp

    # Security
    src/security/hash_password.cpp
    src/security/range_key.cpp

    # SSC: Opal
    src/ssc/opal/opal_session.cpp
    src/ssc/opal/opal_admin.cpp
    src/ssc/opal/opal_locking.cpp
    src/ssc/opal/opal_user.cpp
    src/ssc/opal/opal_mbr.cpp
    src/ssc/opal/opal_data_store.cpp
    src/ssc/opal/opal_device.cpp

    # SSC: Enterprise
    src/ssc/enterprise/enterprise_session.cpp
    src/ssc/enterprise/enterprise_auth.cpp
    src/ssc/enterprise/enterprise_band.cpp
    src/ssc/enterprise/enterprise_erase.cpp
    src/ssc/enterprise/enterprise_device.cpp

    # SSC: Pyrite
    src/ssc/pyrite/pyrite_session.cpp
    src/ssc/pyrite/pyrite_locking.cpp
    src/ssc/pyrite/pyrite_device.cpp

    # Debug / Test Layer
    src/debug/test_context.cpp
    src/debug/command_logger.cpp
    src/debug/logging_transport.cpp

    # Eval API (flat step-by-step)
    src/eval/eval_api.cpp
    src/eval/eval_composite.cpp
)

# ══════════════════════════════════════════════════════
#  Library target
# ══════════════════════════════════════════════════════
if(LIBSED_BUILD_SHARED)
    add_library(libsed SHARED ${LIBSED_SOURCES})
else()
    add_library(libsed STATIC ${LIBSED_SOURCES})
endif()

target_include_directories(libsed PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(libsed PUBLIC cxx_std_17)

# Compiler warnings
target_compile_options(libsed PRIVATE
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

# Platform-specific linking
if(UNIX AND NOT APPLE)
    # Linux: may need pthread
    find_package(Threads)
    if(Threads_FOUND)
        target_link_libraries(libsed PRIVATE Threads::Threads)
    endif()
endif()

# ══════════════════════════════════════════════════════
#  Tests
# ══════════════════════════════════════════════════════
if(LIBSED_BUILD_TESTS)
    enable_testing()

    # Try to find Google Test
    find_package(GTest QUIET)

    if(GTest_FOUND)
        add_executable(libsed_tests
            tests/unit/test_token_codec.cpp
            tests/unit/test_packet.cpp
            tests/unit/test_discovery.cpp
            tests/unit/test_hash.cpp
            tests/unit/test_endian.cpp
            tests/mock/mock_transport.cpp
        )
        target_link_libraries(libsed_tests PRIVATE libsed GTest::gtest GTest::gtest_main)
        target_include_directories(libsed_tests PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
        )

        include(GoogleTest)
        gtest_discover_tests(libsed_tests)
    else()
        message(STATUS "Google Test not found - building standalone test runner")
        add_executable(libsed_tests
            tests/unit/test_token_codec.cpp
            tests/unit/test_packet.cpp
            tests/unit/test_discovery.cpp
            tests/unit/test_hash.cpp
            tests/unit/test_endian.cpp
            tests/mock/mock_transport.cpp
            tests/test_main.cpp
        )
        target_link_libraries(libsed_tests PRIVATE libsed)
        target_include_directories(libsed_tests PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
        )
        add_test(NAME libsed_tests COMMAND libsed_tests)
    endif()
endif()

# ══════════════════════════════════════════════════════
#  Examples
# ══════════════════════════════════════════════════════
if(LIBSED_BUILD_EXAMPLES)
    add_executable(example_opal_setup    examples/opal_setup.cpp)
    add_executable(example_lock_unlock   examples/lock_unlock.cpp)
    add_executable(example_enterprise    examples/enterprise_band.cpp)
    add_executable(example_discovery     examples/discovery.cpp)
    add_executable(example_eval_fault    examples/eval_fault_injection.cpp)
    add_executable(example_eval_steps   examples/eval_step_by_step.cpp)
    add_executable(example_eval_utils   examples/eval_tc_utils.cpp)
    add_executable(example_eval_full    examples/eval_full_demo.cpp)
    add_executable(example_eval_multi   examples/eval_multi_session.cpp)
    add_executable(example_eval_worker  examples/eval_worker_pattern.cpp)
    add_executable(example_eval_reset   examples/eval_reset_scenarios.cpp)

    target_link_libraries(example_opal_setup    PRIVATE libsed)
    target_link_libraries(example_lock_unlock   PRIVATE libsed)
    target_link_libraries(example_enterprise    PRIVATE libsed)
    target_link_libraries(example_discovery     PRIVATE libsed)
    target_link_libraries(example_eval_fault    PRIVATE libsed)
    target_link_libraries(example_eval_steps    PRIVATE libsed)
    target_link_libraries(example_eval_utils    PRIVATE libsed)
    target_link_libraries(example_eval_full     PRIVATE libsed)
    target_link_libraries(example_eval_multi    PRIVATE libsed Threads::Threads)
    target_link_libraries(example_eval_worker   PRIVATE libsed Threads::Threads)
    target_link_libraries(example_eval_reset    PRIVATE libsed Threads::Threads)

    # ── Application Note Examples ──
    add_executable(appnote_opal        examples/appnote_opal.cpp)
    add_executable(appnote_enterprise  examples/appnote_enterprise.cpp)
    add_executable(appnote_mbr         examples/appnote_mbr.cpp)
    add_executable(appnote_psid        examples/appnote_psid.cpp)
    add_executable(appnote_datastore   examples/appnote_datastore.cpp)
    add_executable(appnote_block_sid   examples/appnote_block_sid.cpp)
    add_executable(appnote_ns_locking  examples/appnote_ns_locking.cpp)
    target_link_libraries(appnote_opal        PRIVATE libsed)
    target_link_libraries(appnote_enterprise  PRIVATE libsed)
    target_link_libraries(appnote_mbr         PRIVATE libsed)
    target_link_libraries(appnote_psid        PRIVATE libsed)
    target_link_libraries(appnote_datastore   PRIVATE libsed)
    target_link_libraries(appnote_block_sid   PRIVATE libsed)
    target_link_libraries(appnote_ns_locking  PRIVATE libsed)

    # ── Basic Check (single session) ──
    add_executable(example_eval_basic examples/eval_basic_check.cpp)
    target_link_libraries(example_eval_basic PRIVATE libsed)

    # ── Comprehensive Multi-Thread TC ──
    add_executable(example_eval_mt_comp examples/eval_mt_comprehensive.cpp)
    target_link_libraries(example_eval_mt_comp PRIVATE libsed Threads::Threads)
endif()

# ══════════════════════════════════════════════════════
#  Tools
# ══════════════════════════════════════════════════════
if(LIBSED_BUILD_TOOLS)
    add_executable(sed_discover  tools/sed_discover.cpp)
    add_executable(sed_manage    tools/sed_manage.cpp)
    add_executable(token_dump    tools/token_dump.cpp)

    target_link_libraries(sed_discover  PRIVATE libsed)
    target_link_libraries(sed_manage    PRIVATE libsed)
    target_link_libraries(token_dump    PRIVATE libsed)
endif()

# ══════════════════════════════════════════════════════
#  Install
# ══════════════════════════════════════════════════════
install(TARGETS libsed
    EXPORT libsed-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/libsed
    DESTINATION include
)

install(EXPORT libsed-targets
    FILE libsed-config.cmake
    NAMESPACE libsed::
    DESTINATION lib/cmake/libsed
)
