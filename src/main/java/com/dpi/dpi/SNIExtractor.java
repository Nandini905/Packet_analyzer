package com.dpi.dpi;

import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) hostname from a TLS Client Hello.
 *
 * C++ mapping: SNIExtractor (sni_extractor.h / sni_extractor.cpp)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY SNI MATTERS FOR DPI
 * ─────────────────────────────────────────────────────────────────────────────
 * HTTPS traffic is encrypted, but the very first packet of a TLS session
 * (the "Client Hello") contains the target hostname in PLAINTEXT inside the
 * SNI extension.  This is the only window we have to identify the destination
 * before the session is fully encrypted.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * TLS CLIENT HELLO WIRE FORMAT (simplified)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *  TLS Record Layer (5 bytes):
 *    [0]     Content Type  = 0x16  (Handshake)
 *    [1-2]   Version       = 0x0301 (TLS 1.0) … 0x0304 (TLS 1.3)
 *    [3-4]   Record Length (big-endian)
 *
 *  Handshake Layer (4 bytes):
 *    [5]     Handshake Type = 0x01  (Client Hello)
 *    [6-8]   Handshake Length (3-byte big-endian)
 *
 *  Client Hello Body:
 *    [9-10]  Client Version
 *    [11-42] Random (32 bytes)
 *    [43]    Session ID Length  (N)
 *    [44..44+N-1]  Session ID
 *    [44+N .. 44+N+1]  Cipher Suites Length (C)
 *    [44+N+2 .. 44+N+1+C]  Cipher Suites
 *    [next]  Compression Methods Length (M)
 *    [next+1 .. next+M]  Compression Methods
 *    [next]  Extensions Length (E, 2 bytes)
 *    Extensions:
 *      For each extension:
 *        [0-1]  Extension Type  (2 bytes)
 *        [2-3]  Extension Data Length (2 bytes)
 *        [4..]  Extension Data
 *
 *  SNI Extension (type = 0x0000):
 *    [0-1]  SNI List Length
 *    [2]    SNI Type = 0x00 (hostname)
 *    [3-4]  Hostname Length
 *    [5..]  Hostname bytes (ASCII)   ← THIS IS WHAT WE EXTRACT
 * ─────────────────────────────────────────────────────────────────────────────
 */
public final class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI          = 0x0000;
    private static final int SNI_TYPE_HOSTNAME      = 0x00;

    private SNIExtractor() {}

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Attempt to extract the SNI hostname from a TLS Client Hello payload.
     *
     * @param payload raw TCP payload bytes
     * @param offset  start of payload within the array
     * @param length  number of bytes available from offset
     * @return Optional containing the hostname string, or empty if not found
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) return Optional.empty();

        // ---- skip TLS record header (5 bytes) ----
        int pos = offset + 5;

        // ---- skip Handshake header: type(1) + length(3) ----
        if (pos + 4 > offset + length) return Optional.empty();
        pos += 4;

        // ---- Client Hello body ----

        // Client Version (2 bytes)
        pos += 2;

        // Random (32 bytes)
        pos += 32;

        // Session ID
        if (pos >= offset + length) return Optional.empty();
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Cipher Suites
        if (pos + 2 > offset + length) return Optional.empty();
        int cipherSuitesLen = readUint16BE(payload, pos);
        pos += 2 + cipherSuitesLen;

        // Compression Methods
        if (pos >= offset + length) return Optional.empty();
        int compressionLen = payload[pos] & 0xFF;
        pos += 1 + compressionLen;

        // Extensions total length
        if (pos + 2 > offset + length) return Optional.empty();
        int extensionsLen = readUint16BE(payload, pos);
        pos += 2;

        int extensionsEnd = Math.min(pos + extensionsLen, offset + length);

        // ---- Walk extensions looking for SNI (type 0x0000) ----
        while (pos + 4 <= extensionsEnd) {
            int extType   = readUint16BE(payload, pos);
            int extLength = readUint16BE(payload, pos + 2);
            pos += 4;

            if (pos + extLength > extensionsEnd) break;

            if (extType == EXTENSION_SNI) {
                /*
                 * SNI extension data layout:
                 *   [0-1]  SNI list length
                 *   [2]    SNI entry type (0x00 = hostname)
                 *   [3-4]  Hostname length
                 *   [5..]  Hostname bytes
                 */
                if (extLength < 5) break;

                // skip SNI list length (2 bytes) → pos+0, pos+1
                int sniType   = payload[pos + 2] & 0xFF;
                int sniLength = readUint16BE(payload, pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extLength - 5)    break;

                return Optional.of(new String(payload, pos + 5, sniLength));
            }

            pos += extLength;
        }

        return Optional.empty();
    }

    /**
     * Quick check: does this payload look like a TLS Client Hello?
     * Used to avoid running the full parser on non-TLS traffic.
     */
    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < 9) return false;
        // Content type must be Handshake (0x16)
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;
        // TLS version: 0x0300 (SSL 3.0) … 0x0304 (TLS 1.3)
        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;
        // Record length must fit within available data
        int recordLen = readUint16BE(payload, offset + 3);
        if (recordLen > length - 5) return false;
        // Handshake type must be Client Hello (0x01)
        return (payload[offset + 5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    // -----------------------------------------------------------------------
    // Byte helpers
    // -----------------------------------------------------------------------

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
