package com.iotsecurity.soc.model;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Detection rules used by the SOC detection engine."
)
public enum DetectionRule {

    @Schema(
            description = "Detects five or more failed login attempts from the same user or source IP within five minutes."
    )
    MULTIPLE_FAILED_LOGINS,

    @Schema(
            description = "Detects repeated HTTP 401 or 403 responses against protected endpoints."
    )
    UNAUTHORIZED_ENDPOINT_ACCESS,

    @Schema(
            description = "Detects repeated HTTP 500 responses from the same service within five minutes."
    )
    SERVICE_FAILURE,

    @Schema(
            description = "Detects more than 100 HTTP requests from the same source IP within one minute."
    )
    ABNORMAL_REQUEST_RATE
}