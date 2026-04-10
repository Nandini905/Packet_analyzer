package com.dpi.dpi;

import java.util.Optional;

/**
 * Extracts the queried domain name from a DNS request payload.
 *
 * C++ mapping: DNSExtractor (sni_extractor.h / sni_extractor.cpp)
 *
 * DNS wire format (RFC 1035):
 *   Header (12 bytes):
 *     [0-1]  Transaction ID
 *     [2-3]  Flags  (QR bit = 0 for query, 1 for response)
 *     [4-5]  QDCOUNT (number of questions)
 *     [6-7]  ANCOUNT
 *     [8-9]  NSCOUNT
 *     [10-11] ARCOUNT
 *   Question section:
 *     QNAME: sequence of length-prefixed labels, terminated by 0x00
 *     QTYPE  (2 bytes)
 *     QCLASS (2 bytes)
 *
 * Example: "www.google.com" is encoded as:
 *   03 'w' 'w' 'w'  06 'g' 'o' 'o' 'g' 'l' 'e'  03 'c' 'o' 'm'  00
 */
public final class DNSExtractor {

    private DNSExtractor() {}

    /**
     * Returns true if the payload looks like a DNS query (not a response).
     * Checks the QR bit and that QDCOUNT > 0.
     */
    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;
        // QR bit is bit 7 of byte 2; 0 = query, 1 = response
        if ((payload[offset + 2] & 0x80) != 0) return false;
        // QDCOUNT must be at least 1
        int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        return qdcount > 0;
    }

    /**
     * Extract the first queried domain name from a DNS request.
     *
     * @param payload raw UDP payload bytes
     * @param offset  start of payload within the array
     * @param length  number of bytes available from offset
     * @return Optional containing the domain string (e.g. "www.google.com"),
     *         or empty if not a valid DNS query
     */
    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDNSQuery(payload, offset, length)) return Optional.empty();

        // Question section starts at byte 12 (after the 12-byte header)
        int pos = offset + 12;
        StringBuilder domain = new StringBuilder();

        while (pos < offset + length) {
            int labelLen = payload[pos] & 0xFF;

            if (labelLen == 0) break;           // root label → end of QNAME

            if (labelLen > 63) break;           // compression pointer or invalid label

            pos++;
            if (pos + labelLen > offset + length) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, pos, labelLen));
            pos += labelLen;
        }

        return domain.isEmpty() ? Optional.empty() : Optional.of(domain.toString());
    }
}
