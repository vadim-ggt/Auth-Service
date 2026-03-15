package com.innowise.authservice.domain.exception;

import com.innowise.authservice.web.dto.ErrorResponseDto;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.EntityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.time.LocalDateTime;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(TokenRefreshException.class)
    public ResponseEntity<ErrorResponseDto> handleTokenRefreshException(
            TokenRefreshException ex, WebRequest request) {

        return buildErrorResponse(
                ex,
                ex.getMessage(),
                HttpStatus.FORBIDDEN,
                request
        );
    }



    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponseDto> handleDataIntegrityViolation(
            DataIntegrityViolationException ex, WebRequest request) {

        String message = "Database conflict. A resource with these details already exists.";
        logger.warn("Data integrity violation: {}", ex.getMostSpecificCause().getMessage());

        return buildErrorResponse(
                ex,
                "A resource with these details already exists or violates data constraints.",
                HttpStatus.CONFLICT,
                request
        );
    }

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ErrorResponseDto> handleEntityNotFoundException(
            EntityNotFoundException ex, WebRequest request) {

        return buildErrorResponse(
                ex,
                ex.getMessage(),
                HttpStatus.NOT_FOUND,
                request
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDto> handleValidationExceptions(
            MethodArgumentNotValidException ex, WebRequest request) {

        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));

        return buildErrorResponse(
                ex,
                errorMessage,
                HttpStatus.BAD_REQUEST,
                request
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponseDto> handleMalformedJson(
            HttpMessageNotReadableException ex, WebRequest request) {

        return buildErrorResponse(
                ex,
                "Invalid request body: JSON is malformed.",
                HttpStatus.BAD_REQUEST,
                request
        );
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponseDto> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {

        return buildErrorResponse(
                ex,
                "Authentication failed: " + ex.getMessage(),
                HttpStatus.UNAUTHORIZED,
                request
        );
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponseDto> handleNoResourceFoundException(
            NoResourceFoundException ex, WebRequest request) {

        return buildErrorResponse(
                ex,
                "Endpoint not found: " + ex.getResourcePath(),
                HttpStatus.NOT_FOUND,
                request
        );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponseDto> handleAccessDeniedException(
            AccessDeniedException ex, WebRequest request) {

        return buildErrorResponse(
                ex,
                "Access Denied: You do not have permission to access this resource.",
                HttpStatus.FORBIDDEN,
                request
        );
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponseDto> handleBadCredentials(
            BadCredentialsException ex, WebRequest request) {

        return buildErrorResponse(
                ex, "Invalid username or password",
                HttpStatus.UNAUTHORIZED, request
        );
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponseDto> handleUsernameNotFound(
            UsernameNotFoundException ex, WebRequest request) {

        return buildErrorResponse(
                ex, ex.getMessage(),
                HttpStatus.NOT_FOUND, request
        );
    }


    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ErrorResponseDto> handleBusinessException(
            BusinessException ex, WebRequest request) {

        logger.warn("Business error: {}", ex.getMessage());

        return buildErrorResponse(
                ex,
                ex.getMessage(),
                ex.getStatus(),
                request
        );
    }

    @ExceptionHandler({ExpiredJwtException.class, JwtException.class})
    public ResponseEntity<ErrorResponseDto> handleJwtErrors(
            JwtException ex, WebRequest request) {

        return buildErrorResponse(
                ex, "JWT Token is expired or invalid: " + ex.getMessage(),
                HttpStatus.UNAUTHORIZED, request
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDto> handleGlobalException(
            Exception ex, WebRequest request) {

        logger.error("Unhandled exception caught: {}", ex.getMessage(), ex);

        return buildErrorResponse(
                ex,
                "An unexpected internal server error occurred.",
                HttpStatus.INTERNAL_SERVER_ERROR,
                request
        );
    }



    private ResponseEntity<ErrorResponseDto> buildErrorResponse(
            Exception ex, String message, HttpStatus status, WebRequest request) {

        ErrorResponseDto errorDto = new ErrorResponseDto(
                LocalDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                message,
                request.getDescription(false).replace("uri=", "")
        );

        return new ResponseEntity<>(errorDto, status);
    }

}
