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

    # Facade
    src/facade/sed_drive.cpp

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
    src/security/secure_erase.cpp

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
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
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
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)

    # ── basic/ — 고수준 API 입문 예제 ──
    add_executable(example_discovery     examples/basic/discovery.cpp)
    add_executable(example_opal_setup    examples/basic/opal_setup.cpp)
    add_executable(example_lock_unlock   examples/basic/lock_unlock.cpp)
    add_executable(example_enterprise    examples/basic/enterprise_band.cpp)

    target_link_libraries(example_discovery     PRIVATE libsed)
    target_link_libraries(example_opal_setup    PRIVATE libsed)
    target_link_libraries(example_lock_unlock   PRIVATE libsed)
    target_link_libraries(example_enterprise    PRIVATE libsed)

    # ── appnote/ — TCG Application Note 구현 ──
    add_executable(appnote_opal        examples/appnote/appnote_opal.cpp)
    add_executable(appnote_enterprise  examples/appnote/appnote_enterprise.cpp)
    add_executable(appnote_mbr         examples/appnote/appnote_mbr.cpp)
    add_executable(appnote_psid        examples/appnote/appnote_psid.cpp)
    add_executable(appnote_datastore   examples/appnote/appnote_datastore.cpp)
    add_executable(appnote_block_sid   examples/appnote/appnote_block_sid.cpp)
    add_executable(appnote_ns_locking  examples/appnote/appnote_ns_locking.cpp)

    target_link_libraries(appnote_opal        PRIVATE libsed)
    target_link_libraries(appnote_enterprise  PRIVATE libsed)
    target_link_libraries(appnote_mbr         PRIVATE libsed)
    target_link_libraries(appnote_psid        PRIVATE libsed)
    target_link_libraries(appnote_datastore   PRIVATE libsed)
    target_link_libraries(appnote_block_sid   PRIVATE libsed)
    target_link_libraries(appnote_ns_locking  PRIVATE libsed)

    # ── eval/ — EvalApi 평가 예제 ──
    add_executable(eval_query_flow     examples/eval/query_flow.cpp)
    add_executable(eval_step_by_step   examples/eval/step_by_step.cpp)
    add_executable(eval_full_demo      examples/eval/full_demo.cpp)
    add_executable(eval_tc_utils       examples/eval/tc_utils.cpp)
    add_executable(eval_worker         examples/eval/worker_pattern.cpp)
    add_executable(eval_multithread    examples/eval/multithread.cpp)
    add_executable(eval_reset          examples/eval/reset_scenarios.cpp)

    target_link_libraries(eval_query_flow     PRIVATE libsed)
    target_link_libraries(eval_step_by_step   PRIVATE libsed)
    target_link_libraries(eval_full_demo      PRIVATE libsed)
    target_link_libraries(eval_tc_utils       PRIVATE libsed)
    target_link_libraries(eval_worker         PRIVATE libsed Threads::Threads)
    target_link_libraries(eval_multithread    PRIVATE libsed Threads::Threads)
    target_link_libraries(eval_reset          PRIVATE libsed Threads::Threads)

    # ── facade/ — SedDrive facade 예제 (TC 개발자 추천) ──
    add_executable(facade_query          examples/facade/01_query.cpp)
    add_executable(facade_take_ownership examples/facade/02_take_ownership.cpp)
    add_executable(facade_opal_setup     examples/facade/03_opal_full_setup.cpp)
    add_executable(facade_multi_session  examples/facade/04_multi_session.cpp)
    add_executable(facade_multi_pf       examples/facade/05_multi_pf.cpp)
    add_executable(facade_enterprise     examples/facade/06_enterprise_band.cpp)
    add_executable(facade_revert         examples/facade/07_revert.cpp)

    add_executable(facade_aging          examples/facade/08_aging_4session.cpp)

    target_link_libraries(facade_query          PRIVATE libsed)
    target_link_libraries(facade_take_ownership PRIVATE libsed)
    target_link_libraries(facade_opal_setup     PRIVATE libsed)
    target_link_libraries(facade_multi_session  PRIVATE libsed)
    target_link_libraries(facade_multi_pf       PRIVATE libsed)
    target_link_libraries(facade_enterprise     PRIVATE libsed)
    target_link_libraries(facade_revert         PRIVATE libsed)
    target_link_libraries(facade_aging          PRIVATE libsed)
endif()

# ══════════════════════════════════════════════════════
#  Tools
# ══════════════════════════════════════════════════════
if(LIBSED_BUILD_TOOLS)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)

    add_executable(sed_discover  tools/sed_discover.cpp)
    add_executable(sed_manage    tools/sed_manage.cpp)
    add_executable(token_dump    tools/token_dump.cpp)

    target_link_libraries(sed_discover    PRIVATE libsed)
    target_link_libraries(sed_manage      PRIVATE libsed)
    target_link_libraries(token_dump      PRIVATE libsed)
endif()

# ── Integration tests (offline, no hardware) ──
if(LIBSED_BUILD_TESTS)
    add_executable(ioctl_validator
        tests/integration/ioctl_validator.cpp
        third_party/sedutil/DtaCommand.cpp
        third_party/sedutil/DtaHexDump.cpp
    )
    target_include_directories(ioctl_validator PRIVATE third_party/sedutil)
    target_link_libraries(ioctl_validator PRIVATE libsed)
    set_target_properties(ioctl_validator PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME ioctl_validator COMMAND ioctl_validator)

    add_executable(golden_validator
        tests/integration/golden_validator.cpp
    )
    target_link_libraries(golden_validator PRIVATE libsed)
    target_compile_definitions(golden_validator PRIVATE
        GOLDEN_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/golden")
    set_target_properties(golden_validator PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME golden_validator COMMAND golden_validator)
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
