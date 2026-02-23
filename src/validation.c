#include "../include/validation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int validate_message(const char *msg)
{
    if (!msg || strlen(msg) == 0) {
        return 0;  // Empty message
    }
    if (strlen(msg) > MAX_MESSAGE_LENGTH) {
        return 0;  // Too long
    }
    
    // Check for valid UTF-8 and control characters
    if (!is_valid_utf8(msg)) {
        return 0;
    }
    
    // Reject messages with only whitespace
    const char *p = msg;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '\0') {
        return 0;
    }
    
    return 1;  // Valid
}

int validate_username(const char *username)
{
    if (!username || strlen(username) < 3) {
        return 0;
    }
    if (strlen(username) > MAX_USERNAME_LENGTH) {
        return 0;
    }
    
    // Alphanumeric + underscore + hyphen allowed
    for (size_t i = 0; i < strlen(username); i++) {
        char c = username[i];
        if (!isalnum((unsigned char)c) && c != '_' && c != '-') {
            return 0;
        }
    }
    
    // Cannot start with number
    if (isdigit((unsigned char)username[0])) {
        return 0;
    }
    
    return 1;
}

int validate_email(const char *email)
{
    if (!email || strlen(email) < 5 || strlen(email) > MAX_EMAIL_LENGTH) {
        return 0;
    }
    
    // Very basic email validation: must contain @ and .
    const char *at = strchr(email, '@');
    if (!at || at == email) {
        return 0;
    }
    
    const char *dot = strchr(at, '.');
    if (!dot || dot == at + 1 || dot[1] == '\0') {
        return 0;
    }
    
    // Check for valid characters
    for (const char *p = email; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '@' && *p != '.' && 
            *p != '_' && *p != '-') {
            return 0;
        }
    }
    
    return 1;
}

int validate_password(const char *password)
{
    if (!password || strlen(password) < MIN_PASSWORD_LENGTH) {
        return 0;
    }
    if (strlen(password) > MAX_PASSWORD_LENGTH) {
        return 0;
    }
    
    // At least one uppercase, one lowercase, one digit, one special char
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    
    for (const char *p = password; *p; p++) {
        if (isupper((unsigned char)*p)) has_upper = 1;
        else if (islower((unsigned char)*p)) has_lower = 1;
        else if (isdigit((unsigned char)*p)) has_digit = 1;
        else if (*p == '!' || *p == '@' || *p == '#' || *p == '$' || 
                 *p == '%' || *p == '^' || *p == '&' || *p == '*' ||
                 *p == '(' || *p == ')' || *p == '-' || *p == '_' ||
                 *p == '=' || *p == '+') {
            has_special = 1;
        }
    }
    
    return has_upper && has_lower && has_digit && has_special;
}

int is_valid_utf8(const char *str)
{
    if (!str) return 0;
    
    unsigned char *p = (unsigned char *)str;
    while (*p) {
        // Single byte character (0xxxxxxx)
        if ((p[0] & 0x80) == 0) {
            // Reject control characters except tab, newline, carriage return
            if (*p < 32 && *p != '\t' && *p != '\n' && *p != '\r') {
                return 0;
            }
            p++;
        }
        // Two byte character (110xxxxx 10xxxxxx)
        else if ((p[0] & 0xE0) == 0xC0) {
            if ((p[1] & 0xC0) != 0x80) return 0;
            p += 2;
        }
        // Three byte character (1110xxxx 10xxxxxx 10xxxxxx)
        else if ((p[0] & 0xF0) == 0xE0) {
            if ((p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) return 0;
            p += 3;
        }
        // Four byte character (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
        else if ((p[0] & 0xF8) == 0xF0) {
            if ((p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 || 
                (p[3] & 0xC0) != 0x80) return 0;
            p += 4;
        }
        else {
            return 0;  // Invalid UTF-8
        }
    }
    
    return 1;
}

char *sanitize_html(const char *input)
{
    if (!input) return calloc(1, 1);
    
    size_t output_size = strlen(input) * 6 + 1;  // Worst case: all chars need escaping
    char *output = (char *)malloc(output_size);
    if (!output) return NULL;
    
    char *p = output;
    const char *q = input;
    
    while (*q && (size_t)(p - output) < output_size - 6) {
        switch (*q) {
            case '<':
                strcpy(p, "&lt;");
                p += 4;
                break;
            case '>':
                strcpy(p, "&gt;");
                p += 4;
                break;
            case '&':
                strcpy(p, "&amp;");
                p += 5;
                break;
            case '"':
                strcpy(p, "&quot;");
                p += 6;
                break;
            case '\'':
                strcpy(p, "&#x27;");
                p += 6;
                break;
            default:
                *p++ = *q;
        }
        q++;
    }
    *p = '\0';
    
    return output;
}
