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
    src/transport/sim_transport.cpp

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

    # Eval API (flat step-by-step) — split by category
    src/eval/eval_api.cpp
    src/eval/eval_api_table.cpp
    src/eval/eval_api_locking.cpp
    src/eval/eval_api_user.cpp
    src/eval/eval_api_enterprise.cpp
    src/eval/eval_api_tclib.cpp
    src/eval/eval_api_nvme.cpp
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

    # ── Beginner (01-06): Discovery → Properties → Sessions → MSID → Ownership → Activation ──
    add_executable(01_hello_discovery    examples/01_hello_discovery.cpp)
    add_executable(02_properties         examples/02_properties.cpp)
    add_executable(03_sessions           examples/03_sessions.cpp)
    add_executable(04_read_msid          examples/04_read_msid.cpp)
    add_executable(05_take_ownership     examples/05_take_ownership.cpp)
    add_executable(06_activate_locking   examples/06_activate_locking.cpp)

    target_link_libraries(01_hello_discovery    PRIVATE libsed)
    target_link_libraries(02_properties         PRIVATE libsed)
    target_link_libraries(03_sessions           PRIVATE libsed)
    target_link_libraries(04_read_msid          PRIVATE libsed)
    target_link_libraries(05_take_ownership     PRIVATE libsed)
    target_link_libraries(06_activate_locking   PRIVATE libsed)

    # ── Core Opal (07-12): Ranges → Users → MBR → DataStore → CryptoErase → Reset ──
    add_executable(07_locking_ranges     examples/07_locking_ranges.cpp)
    add_executable(08_user_management    examples/08_user_management.cpp)
    add_executable(09_mbr_shadow         examples/09_mbr_shadow.cpp)
    add_executable(10_datastore          examples/10_datastore.cpp)
    add_executable(11_crypto_erase       examples/11_crypto_erase.cpp)
    add_executable(12_factory_reset      examples/12_factory_reset.cpp)

    target_link_libraries(07_locking_ranges     PRIVATE libsed)
    target_link_libraries(08_user_management    PRIVATE libsed)
    target_link_libraries(09_mbr_shadow         PRIVATE libsed)
    target_link_libraries(10_datastore          PRIVATE libsed)
    target_link_libraries(11_crypto_erase       PRIVATE libsed)
    target_link_libraries(12_factory_reset      PRIVATE libsed)

    # ── Enterprise (13) ──
    add_executable(13_enterprise_bands   examples/13_enterprise_bands.cpp)
    target_link_libraries(13_enterprise_bands   PRIVATE libsed)

    # ── Expert (14-20): Errors → Wire → EvalApi → Composite → Faults → Threading → Transport ──
    add_executable(14_error_handling      examples/14_error_handling.cpp)
    add_executable(15_wire_inspection     examples/15_wire_inspection.cpp)
    add_executable(16_eval_step_by_step   examples/16_eval_step_by_step.cpp)
    add_executable(17_composite_patterns  examples/17_composite_patterns.cpp)
    add_executable(18_fault_injection     examples/18_fault_injection.cpp)
    add_executable(19_multi_session       examples/19_multi_session.cpp)
    add_executable(20_custom_transport    examples/20_custom_transport.cpp)

    target_link_libraries(14_error_handling      PRIVATE libsed)
    target_link_libraries(15_wire_inspection     PRIVATE libsed)
    target_link_libraries(16_eval_step_by_step   PRIVATE libsed)
    target_link_libraries(17_composite_patterns  PRIVATE libsed)
    target_link_libraries(18_fault_injection     PRIVATE libsed)
    target_link_libraries(19_multi_session       PRIVATE libsed Threads::Threads)
    target_link_libraries(20_custom_transport    PRIVATE libsed)
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

    # ── Scenario tests (L1~L5, 102 scenarios) ──
    add_executable(scenario_tests
        tests/scenarios/scenario_main.cpp
        tests/scenarios/test_L1_basic.cpp
        tests/scenarios/test_L2_sequence.cpp
        tests/scenarios/test_L3_cross.cpp
        tests/scenarios/test_L4_negative.cpp
        tests/scenarios/test_L5_advanced.cpp
        tests/scenarios/test_sim_basic.cpp
        tests/scenarios/test_sim_comprehensive.cpp
        tests/mock/mock_transport.cpp
    )
    target_include_directories(scenario_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(scenario_tests PRIVATE libsed)
    set_target_properties(scenario_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME scenario_tests COMMAND scenario_tests)

    # ── Device runner (real hardware test) ──
    add_executable(device_runner
        tests/scenarios/device_runner.cpp
    )
    target_link_libraries(device_runner PRIVATE libsed)
    set_target_properties(device_runner PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

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
