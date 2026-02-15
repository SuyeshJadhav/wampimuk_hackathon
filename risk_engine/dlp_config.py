"""
DLP Sensitivity Score Configuration

Change scores here without modifying scanner logic.
Higher score = more sensitive
"""

SENSITIVITY_SCORES = {

    # Critical Identity
    "SSN": 10,
    "CREDIT_CARD": 10,
    "DRIVER_LICENSE": 9,
    "PASSPORT": 9,

    # Financial
    "BANK_ACCOUNT": 8,
    "ROUTING_NUMBER": 8,
    "SWIFT_CODES": 8,
    "IBAN": 8,

    # Authentication
    "API_KEY": 9,
    "PRIVATE_KEY": 10,
    "PASSWORD": 7,

    # Personal
    "EMAIL": 4,
    "PHONE": 4,
    "ADDRESS": 5,

    # Low sensitivity
    "NAME": 1,

}
