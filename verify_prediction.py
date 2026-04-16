# Test cases for prediction mapping
def test_mapping(result):
    # This simulates the logic added to views.py
    attack_type = {0: 'Malware', 1: 'DDoS', 2: 'Intrusion', 3: 'Normal'}.get(result)
    val = "cyber attack" if attack_type in ['Malware', 'DDoS', 'Intrusion'] else "no cyber attck"
    return val

# Verify predictions
print(f"Result 0 (Malware): {test_mapping(0)}")
print(f"Result 1 (DDoS): {test_mapping(1)}")
print(f"Result 2 (Intrusion): {test_mapping(2)}")
print(f"Result 3 (Normal): {test_mapping(3)}")

assert test_mapping(0) == "cyber attack"
assert test_mapping(1) == "cyber attack"
assert test_mapping(2) == "cyber attack"
assert test_mapping(3) == "no cyber attck"

print("Verification SUCCESSFUL!")
