#include <cstdio>
#include <cstdlib>

// Declare run functions from each unit test file
extern void run_token_codec_tests();
extern void run_packet_tests();
extern void run_discovery_tests();
extern void run_hash_tests();
extern void run_endian_tests();
extern void run_method_tests();
extern void run_session_tests();
extern void run_debug_layer_tests();
extern void run_logging_tests();
extern void run_cats_cli_transaction_tests();

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    printf("libsed unit tests\n");
    printf("══════════════════════════════\n");

    run_token_codec_tests();
    run_packet_tests();
    run_discovery_tests();
    run_hash_tests();
    run_endian_tests();
    run_method_tests();
    run_session_tests();
    run_debug_layer_tests();
    run_logging_tests();
    run_cats_cli_transaction_tests();

    printf("\nAll unit tests passed.\n");
    return 0;
}
