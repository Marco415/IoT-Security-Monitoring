import re


class QueryRouter:

    ALERT_PATTERNS = [
        r"\balert\b",
        r"\balerts\b",
        r"\bcreated\b.*\balert\b",
        r"\bwhy was\b.*\balert\b",
        r"\binvestigat",
    ]

    THREAT_PATTERNS = [
        r"\bthreat\b",
        r"\battack\b",
        r"\bcredential attack\b",
        r"\bbrute force\b",
        r"\bmitigat",
        r"\bcontrols?\b",
    ]

    DEPENDENCY_PATTERNS = [
        r"\bdepend",
        r"\bdependency\b",
        r"\bdependencies\b",
        r"\bimpact\b.*\bservice\b",
    ]

    USER_EVENT_PATTERNS = [
        r"\buser\b",
        r"\busers\b",
        r"\bfailed login",
        r"\blogin\b",
        r"\bevents?\b",
    ]

    SERVICE_PATTERNS = [
        r"\bservice\b",
        r"\bauth-service\b",
        r"\bdevice-service\b",
        r"\bevent-service\b",
        r"\bgateway\b",
    ]

    def classify(self, question: str) -> str:

        text = question.lower().strip()

        if self._matches(text, self.ALERT_PATTERNS):
            return "alert_investigation"

        if self._matches(text, self.DEPENDENCY_PATTERNS):
            return "service_dependencies"

        if self._matches(text, self.THREAT_PATTERNS):
            return "threat_controls"

        if self._matches(text, self.USER_EVENT_PATTERNS):
            return "user_events"

        if self._matches(text, self.SERVICE_PATTERNS):
            return "service_information"

        return "security_overview"

    @staticmethod
    def _matches(text: str, patterns: list[str]) -> bool:

        return any(
            re.search(pattern, text)
            for pattern in patterns
        )


query_router = QueryRouter()