package com.dpi.dpi;

import java.util.Optional;

/**
 * Extracts the HTTP Host header value from a plain HTTP/1.x request payload.
 *
 * C++ mapping: HTTPHostExtractor (sni_extractor.h / sni_extractor.cpp)
 *
 * For unencrypted HTTP (port 80) the Host header is in plaintext, giving us
 * the same information as SNI does for HTTPS.
 *
 * HTTP request format (relevant part):
 *   GET /path HTTP/1.1\r\n
 *   Host: www.example.com\r\n
 *   ...
 */
public final class HTTPHostExtractor {

    // First 4 bytes of common HTTP request methods
    private static final byte[][] HTTP_METHODS = {
        "GET ".getBytes(), "POST".getBytes(), "PUT ".getBytes(),
        "HEAD".getBytes(), "DELE".getBytes(), "PATC".getBytes(), "OPTI".getBytes()
    };

    private HTTPHostExtractor() {}

    /**
     * Check whether the payload starts with a known HTTP request method.
     */
    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        for (byte[] method : HTTP_METHODS) {
            if (payload[offset]   == method[0] && payload[offset+1] == method[1]
             && payload[offset+2] == method[2] && payload[offset+3] == method[3]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract the value of the Host header from an HTTP request.
     * Matching is case-insensitive ("host:", "Host:", "HOST:" all work).
     * Port suffix (e.g. ":8080") is stripped from the returned value.
     *
     * @param payload raw TCP payload bytes
     * @param offset  start of payload within the array
     * @param length  number of bytes available from offset
     * @return Optional containing the hostname, or empty if not found
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) return Optional.empty();

        int end = offset + length;

        for (int i = offset; i + 5 < end; i++) {
            // Case-insensitive match for "Host:"
            if (toLower(payload[i])   == 'h'
             && toLower(payload[i+1]) == 'o'
             && toLower(payload[i+2]) == 's'
             && toLower(payload[i+3]) == 't'
             && payload[i+4] == ':') {

                // Skip "Host:" and any leading whitespace
                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find end of line (\r or \n)
                int lineEnd = start;
                while (lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n') {
                    lineEnd++;
                }

                if (lineEnd > start) {
                    String host = new String(payload, start, lineEnd - start).trim();
                    // Strip port if present (e.g. "example.com:8080" → "example.com")
                    int colon = host.lastIndexOf(':');
                    if (colon > 0) host = host.substring(0, colon);
                    return Optional.of(host);
                }
            }
        }
        return Optional.empty();
    }

    private static char toLower(byte b) {
        return Character.toLowerCase((char)(b & 0xFF));
    }
}
