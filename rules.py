
def rule_poisoned_high_rate_StNum(packet: dict) -> bool:
    return packet.get('StNum', 0) > 4849.65



def rule_poisoned_high_rate_timestampDiff(packet: dict) -> bool:
    return packet.get('timestampDiff', 0) > 5.31



def rule_high_StNum_StNum(packet: dict) -> bool:
    return packet.get('StNum', 0) > 43437.13



def rule_high_StNum_stDiff(packet: dict) -> bool:
    return packet.get('stDiff', 0) > 32931.17

def rule_combined_anomaly(packet: dict) -> bool:
    anomalies = 0
    if packet.get('StNum', 0) > 50000:
        anomalies += 1
    if abs(packet.get('stDiff', 0)) > 10:
        anomalies += 1
    if abs(packet.get('sqDiff', 0)) > 10:
        anomalies += 1
    if abs(packet.get('timestampDiff', 0)) > 1:
        anomalies += 1
    return anomalies >= 2

def rule_grayhole_stnum(packet: dict) -> bool:
    return packet.get('StNum', 0) == 0.0 and packet.get('SqNum', 0) != 0.0

def rule_high_stnum(packet: dict) -> bool:
    return packet.get('StNum', 0) > 50000

def rule_injection_stdiff(packet: dict) -> bool:
    return packet.get('stDiff', 0) < -10

def rule_inverse_replay(packet: dict) -> bool:
    return packet.get('StNum', 0) > 300 and packet.get('timestampDiff', 0) > 1000

def rule_masquerade_stdiff(packet: dict) -> bool:
    return abs(packet.get('stDiff', 0)) > 10
