#include <gtest/gtest.h>
#include "IRansomwareDetector.hpp"

TEST(DetectorTest, FactoryCreatesInstance) {
    auto detector = create_ransomware_detector();
    ASSERT_NE(detector, nullptr);
}

TEST(DetectorTest, CalculateEntropyReturnsValue) {
    auto detector = create_ransomware_detector();
    double entropy = detector->calculate_entropy("test.txt");
    EXPECT_GE(entropy, 0.0);
    EXPECT_LE(entropy, 8.0);
}

TEST(DetectorTest, ScanDirectoryReturnsEmpty) {
    auto detector = create_ransomware_detector();
    auto files = detector->scan_directory(".");
    EXPECT_TRUE(files.empty());
}
