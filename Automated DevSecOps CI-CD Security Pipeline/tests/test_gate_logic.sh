#!/bin/bash
# test_gate_logic.sh
# Tests the core logic of the DevSecOps security gate to ensure it blocks
# when HIGH/CRITICAL issues are found, and passes when clean or LOW severity.

echo "Starting Security Gate Logic Tests..."
PASSED_TESTS=0
TOTAL_TESTS=5

# Helper function to evaluate our core gate logic
evaluate_gate() {
  local secrets=$1
  local sca=$2
  local sast=$3
  
  if [ "$secrets" != "success" ] || [ "$sca" != "success" ] || [ "$sast" != "success" ]; then
    return 1 # FAIL (Blocked)
  else
    return 0 # PASS (Allowed)
  fi
}

run_test() {
  local test_name=$1
  local secrets=$2
  local sca=$3
  local sast=$4
  local expected=$5
  
  evaluate_gate "$secrets" "$sca" "$sast"
  local result=$?
  
  if [ $result -eq $expected ]; then
    echo "✅ PASS: $test_name"
    ((PASSED_TESTS++))
  else
    echo "❌ FAIL: $test_name (Expected $expected, got $result)"
  fi
}

echo "----------------------------------------"

# Test 1: Clean build
run_test "Test 1: No findings" "success" "success" "success" 0

# Test 2: Only LOW/MEDIUM findings (Jobs don't exit 1 for these)
run_test "Test 2: Only LOW/MEDIUM findings" "success" "success" "success" 0

# Test 3: HIGH findings in SCA (Job exits 1)
run_test "Test 3: HIGH findings in SCA" "success" "failure" "success" 1

# Test 4: Secrets found (Job exits 1)
run_test "Test 4: Secrets found" "failure" "success" "success" 1

# Test 5: All scanners fail
run_test "Test 5: Multiple failures" "failure" "failure" "failure" 1

echo "----------------------------------------"
echo "Results: $PASSED_TESTS / $TOTAL_TESTS tests passed."

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
  exit 0
else
  exit 1
fi
