#pragma once
#include "INids.hpp"
#include <vector>

// Free function to extract numerical features from a network flow.
// Returns a vector of 14 features used by the ML classifier.
std::vector<double> extract_flow_features(const NetworkFlow& flow);
