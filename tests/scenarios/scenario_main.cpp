/// @file scenario_main.cpp
/// @brief TCG SED Test Scenario Runner — 전체 테스트 실행 진입점
///
/// 실행:
///   ./build/tests/scenario_tests [--level N]
///
/// Level 1: 단위 기능 (20)   Level 2: 표준 시퀀스 (15)
/// Level 3: 연동 검증 (8+)   Level 4: 네거티브 (13+)
/// Level 5: 고급 시나리오 (9+)

#include <cstdio>
#include <cstdlib>
#include <cstring>

// Global counters
int g_passed = 0;
int g_failed = 0;

// Forward declarations for level runners
void run_L1_tests();
void run_L2_tests();
void run_L3_tests();
void run_L4_tests();
void run_L5_tests();
void run_sim_tests();
void run_sim_comprehensive_tests();

int main(int argc, char* argv[]) {
    int targetLevel = 0;  // 0 = 전체

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--level") == 0 && i + 1 < argc) {
            targetLevel = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [--level N]\n", argv[0]);
            printf("  --level 1  Run Level 1 only (Basic Function Tests)\n");
            printf("  --level 2  Run Level 2 only (Standard Sequence Tests)\n");
            printf("  --level 3  Run Level 3 only (Cross-Feature Tests)\n");
            printf("  --level 4  Run Level 4 only (Error & Negative Tests)\n");
            printf("  --level 5  Run Level 5 only (Advanced Scenarios)\n");
            printf("  (no flag)  Run all levels\n");
            return 0;
        }
    }

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   TCG SED Test Scenarios — CATS Validation      ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    if (targetLevel == 0 || targetLevel == 1) run_L1_tests();
    if (targetLevel == 0 || targetLevel == 2) run_L2_tests();
    if (targetLevel == 0 || targetLevel == 3) run_L3_tests();
    if (targetLevel == 0 || targetLevel == 4) run_L4_tests();
    if (targetLevel == 0 || targetLevel == 5) run_L5_tests();
    if (targetLevel == 0 || targetLevel == 6) run_sim_tests();
    if (targetLevel == 0 || targetLevel == 7) run_sim_comprehensive_tests();

    printf("\n══════════════════════════════════════════════════\n");
    printf("  Results: %d PASSED, %d FAILED\n", g_passed, g_failed);
    printf("══════════════════════════════════════════════════\n");

    return g_failed > 0 ? 1 : 0;
}
