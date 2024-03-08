from enum import Enum


class Alert:
    def __init__(self, level, description):
        self.alert_level = level
        self.alert_description = description
