#include <gtest/gtest.h>
#include "IMemoryScanner.hpp"

TEST(ScannerTest, FactoryCreatesInstance) {
    auto scanner = create_memory_scanner();
    ASSERT_NE(scanner, nullptr);
}

TEST(ScannerTest, ListProcessesReturnsNonEmpty) {
    auto scanner = create_memory_scanner();
    auto procs = scanner->list_processes();
    EXPECT_GT(procs.size(), 0);
}