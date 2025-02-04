# Define the CIDR ranges for the Auckland AZ in Nectar Cloud
TEST_CIDR = ""

TARGET_CIDRS = [
]

# Change me to desired security risk type
SECURITY_RISK_TYPE_TARGET = "password-ssh"

# Set lookup dictionary for security risk types
SECURITY_RISK_TYPE_LOOKUP = {
    "vulnerable-http": "b90e99dd-b49d-4110-8d1b-d1581ca474b4",
    "password-ssh": "c59f20bd-cd38-4fd4-be8f-ae2ea88b0460",
    "accessible-db": "cb9feb63-88ba-4016-91ed-347e8806aed8",
    "accessible-rdp": "db27aeb2-6e0f-4aa3-8440-043f131bf979",
}

# Set lookup dictionary for Tenable plugin IDs
SECURITY_RISK_TYPE_TENABLE_PLUGINS = {
    "vulnerable-http": None,
    "password-ssh": [
        149334,  # SSH Password Authentication Accepted
    ],
    "accessible-db": [
        2131,  # SQL Server Detection
        9508,  # Microsoft SQL Server 2008 Detection
        9510,  # Microsoft SQL Server 2012 Detection
        9512,  # Microsoft SQL Server 2016 Detection
        7220,  # Microsoft SQL Server Database Instance Detection
        122583,  # SQL Server Version Detection
    ],
    "accessible-rdp": [
        5954,  # Windows RDP / Terminal Services Detection
        10940,  # Remote Desktop Protocol Service Detection
        27507,  # OS Identification : RDP
    ],
}
