package com.iotsecurity.event.exception;

import com.iotsecurity.event.client.DeviceServiceUnavailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log =
            LoggerFactory.getLogger(
                    GlobalExceptionHandler.class
            );

    private static final String CORRELATION_ID =
            "X-Correlation-ID";

    /**
     * Handles IllegalArgumentException.
     *
     * These are generally client/request-related errors,
     * such as requesting an event that does not exist.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(
            IllegalArgumentException exception) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.warn(
                "Illegal argument while processing security event " +
                        "correlationId={} message={}",
                correlationId,
                exception.getMessage()
        );

        return buildResponse(
                HttpStatus.NOT_FOUND,
                exception.getMessage(),
                correlationId
        );
    }

    /**
     * Handles failures when Event Service cannot communicate
     * with Device Service.
     *
     * This can occur when:
     * - Device Service is unavailable
     * - Retry attempts are exhausted
     * - Circuit breaker is open
     * - Device Service returns an invalid response
     */
    @ExceptionHandler(DeviceServiceUnavailableException.class)
    public ResponseEntity<Map<String, Object>>
    handleDeviceServiceUnavailable(
            DeviceServiceUnavailableException exception) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.error(
                "Device service unavailable " +
                        "correlationId={} message={}",
                correlationId,
                exception.getMessage(),
                exception
        );

        return buildResponse(
                HttpStatus.SERVICE_UNAVAILABLE,
                "Device service is currently unavailable.",
                correlationId
        );
    }

    /**
     * Handles validation failures on incoming Event Service requests.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(
            MethodArgumentNotValidException exception) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        Map<String, String> errors =
                new HashMap<>();

        exception.getBindingResult()
                .getFieldErrors()
                .forEach(error ->
                        errors.put(
                                error.getField(),
                                error.getDefaultMessage()
                        )
                );

        log.warn(
                "Security event request validation failed " +
                        "correlationId={} validationErrors={}",
                correlationId,
                errors
        );

        Map<String, Object> response =
                new HashMap<>();

        response.put(
                "timestamp",
                LocalDateTime.now()
        );

        response.put(
                "status",
                HttpStatus.BAD_REQUEST.value()
        );

        response.put(
                "error",
                "Validation failed"
        );

        response.put(
                "details",
                errors
        );

        response.put(
                "correlationId",
                correlationId
        );

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(response);
    }

    /**
     * Handles malformed JSON and invalid enum values.
     *
     * Examples:
     * - Invalid JSON syntax
     * - Invalid EventType value
     * - Invalid Severity value
     * - Incorrect JSON field types
     *
     * These are client-side request errors and should return
     * HTTP 400 Bad Request instead of HTTP 500 Internal Server Error.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>>
    handleMessageNotReadable(
            HttpMessageNotReadableException exception) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        String causeMessage = null;

        if (exception.getMostSpecificCause() != null) {
            causeMessage =
                    exception.getMostSpecificCause()
                            .getMessage();
        }

        log.warn(
                "Invalid request body received " +
                        "correlationId={} message={}",
                correlationId,
                causeMessage
        );

        String message =
                "Invalid request body. " +
                        "Check the supplied field values.";

        /*
         * Give a more useful message when an invalid enum
         * value is supplied.
         */
        if (causeMessage != null &&
                causeMessage.contains("EventType")) {

            message =
                    "Invalid eventType. " +
                            "Check the supported EventType values.";
        }

        return buildResponse(
                HttpStatus.BAD_REQUEST,
                message,
                correlationId
        );
    }

    /**
     * Handles unexpected exceptions.
     *
     * This handler should only be reached for genuine
     * server-side errors that are not handled above.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>>
    handleGeneralException(
            Exception exception) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.error(
                "Unhandled exception in event service " +
                        "correlationId={}",
                correlationId,
                exception
        );

        return buildResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred.",
                correlationId
        );
    }

    /**
     * Builds a standard error response containing
     * the correlation ID.
     */
    private ResponseEntity<Map<String, Object>> buildResponse(
            HttpStatus status,
            String message,
            String correlationId) {

        Map<String, Object> response =
                new HashMap<>();

        response.put(
                "timestamp",
                LocalDateTime.now()
        );

        response.put(
                "status",
                status.value()
        );

        response.put(
                "error",
                status.getReasonPhrase()
        );

        response.put(
                "message",
                message
        );

        response.put(
                "correlationId",
                correlationId
        );

        return ResponseEntity
                .status(status)
                .body(response);
    }
}