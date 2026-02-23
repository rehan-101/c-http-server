#ifndef VALIDATION_H
#define VALIDATION_H

#include <string.h>
#include <ctype.h>

#define MAX_MESSAGE_LENGTH 4096
#define MAX_USERNAME_LENGTH 32
#define MAX_EMAIL_LENGTH 255
#define MIN_PASSWORD_LENGTH 8
#define MAX_PASSWORD_LENGTH 128

/**
 * Validates message content
 * Returns: 1 if valid, 0 if invalid
 */
int validate_message(const char *msg);

/**
 * Validates username format
 * Returns: 1 if valid, 0 if invalid
 */
int validate_username(const char *username);

/**
 * Validates email format (basic validation)
 * Returns: 1 if valid, 0 if invalid
 */
int validate_email(const char *email);

/**
 * Validates password strength
 * Returns: 1 if valid, 0 if invalid
 */
int validate_password(const char *password);

/**
 * Check if string is valid UTF-8
 * Returns: 1 if valid, 0 if invalid
 */
int is_valid_utf8(const char *str);

/**
 * Escape HTML special characters
 * Returns: Newly allocated escaped string (caller must free)
 */
char *sanitize_html(const char *input);

#endif
