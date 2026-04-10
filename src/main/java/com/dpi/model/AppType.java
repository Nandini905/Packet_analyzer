package com.dpi.model;

/**
 * Enumeration of all application types the DPI engine can classify.
 *
 * C++ mapping: enum class AppType in types.h / types.cpp
 * Each value maps to a known internet service detected via SNI, HTTP Host, or port.
 */
public enum AppType {

    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // ---- Specific applications (detected via SNI / domain pattern) ----
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    // -----------------------------------------------------------------------
    // Display name  (mirrors C++ appTypeToString())
    // -----------------------------------------------------------------------
    public String displayName() {
        return switch (this) {
            case UNKNOWN    -> "Unknown";
            case HTTP       -> "HTTP";
            case HTTPS      -> "HTTPS";
            case DNS        -> "DNS";
            case TLS        -> "TLS";
            case QUIC       -> "QUIC";
            case GOOGLE     -> "Google";
            case FACEBOOK   -> "Facebook";
            case YOUTUBE    -> "YouTube";
            case TWITTER    -> "Twitter/X";
            case INSTAGRAM  -> "Instagram";
            case NETFLIX    -> "Netflix";
            case AMAZON     -> "Amazon";
            case MICROSOFT  -> "Microsoft";
            case APPLE      -> "Apple";
            case WHATSAPP   -> "WhatsApp";
            case TELEGRAM   -> "Telegram";
            case TIKTOK     -> "TikTok";
            case SPOTIFY    -> "Spotify";
            case ZOOM       -> "Zoom";
            case DISCORD    -> "Discord";
            case GITHUB     -> "GitHub";
            case CLOUDFLARE -> "Cloudflare";
        };
    }

    // -----------------------------------------------------------------------
    // SNI → AppType mapping  (mirrors C++ sniToAppType() in types.cpp)
    // Pattern matching is intentionally ordered: more specific first.
    // -----------------------------------------------------------------------
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isBlank()) return UNKNOWN;
        String s = sni.toLowerCase();

        // YouTube must come before Google (youtube.com is owned by Google)
        if (s.contains("youtube") || s.contains("ytimg") || s.contains("youtu.be"))
            return YOUTUBE;

        if (s.contains("instagram") || s.contains("cdninstagram"))
            return INSTAGRAM;

        if (s.contains("whatsapp") || s.contains("wa.me"))
            return WHATSAPP;

        if (s.contains("facebook") || s.contains("fbcdn")
                || s.contains("fb.com") || s.contains("fbsbx") || s.contains("meta.com"))
            return FACEBOOK;

        if (s.contains("twitter") || s.contains("twimg")
                || s.contains("x.com") || s.contains("t.co"))
            return TWITTER;

        if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg"))
            return NETFLIX;

        if (s.contains("amazon") || s.contains("amazonaws")
                || s.contains("cloudfront") || s.contains("aws"))
            return AMAZON;

        if (s.contains("microsoft") || s.contains("msn.com") || s.contains("office")
                || s.contains("azure") || s.contains("live.com")
                || s.contains("outlook") || s.contains("bing"))
            return MICROSOFT;

        if (s.contains("apple") || s.contains("icloud")
                || s.contains("mzstatic") || s.contains("itunes"))
            return APPLE;

        if (s.contains("telegram") || s.contains("t.me"))
            return TELEGRAM;

        if (s.contains("tiktok") || s.contains("tiktokcdn")
                || s.contains("musical.ly") || s.contains("bytedance"))
            return TIKTOK;

        if (s.contains("spotify") || s.contains("scdn.co"))
            return SPOTIFY;

        if (s.contains("zoom"))
            return ZOOM;

        if (s.contains("discord") || s.contains("discordapp"))
            return DISCORD;

        if (s.contains("github") || s.contains("githubusercontent"))
            return GITHUB;

        if (s.contains("cloudflare") || s.contains("cf-"))
            return CLOUDFLARE;

        if (s.contains("google") || s.contains("gstatic")
                || s.contains("googleapis") || s.contains("ggpht") || s.contains("gvt1"))
            return GOOGLE;

        // SNI present but unrecognised → still encrypted HTTPS
        return HTTPS;
    }

    /** Parse a display-name string back to AppType (used when loading rules from file). */
    public static AppType fromDisplayName(String name) {
        for (AppType a : values()) {
            if (a.displayName().equalsIgnoreCase(name)) return a;
        }
        return UNKNOWN;
    }
}
