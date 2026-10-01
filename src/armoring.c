#include "armoring.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* RFC 4880 CRC-24: generator polynomial 0x864CFB, init 0xB704CE */
#define CRC24_INIT 0xB704CE
#define CRC24_POLY 0x1864CFB

static uint32_t compute_crc24(const uint8_t *data, size_t len) {
    uint32_t crc = CRC24_INIT;
    for (size_t i = 0; i < len; i++) {
        crc ^= ((uint32_t)data[i]) << 16;
        for (int b = 0; b < 8; b++) {
            crc <<= 1;
            if (crc & 0x1000000) {
                crc ^= CRC24_POLY;
            }
        }
    }
    return crc & 0xFFFFFF;
}

static const char *get_header(cv_armor_type_t t) {
    switch (t) {
        case CV_ARMOR_MESSAGE: return "-----BEGIN CRYPTOVAULT ENCRYPTED MESSAGE-----";
        case CV_ARMOR_KEY:     return "-----BEGIN CRYPTOVAULT SECRET KEY-----";
        case CV_ARMOR_SHARE:   return "-----BEGIN CRYPTOVAULT KEY SHARE-----";
        case CV_ARMOR_PUBKEY:  return "-----BEGIN CRYPTOVAULT PUBLIC KEY-----";
        default:               return "-----BEGIN CRYPTOVAULT ARMORED DATA-----";
    }
}

static const char *get_footer(cv_armor_type_t t) {
    switch (t) {
        case CV_ARMOR_MESSAGE: return "-----END CRYPTOVAULT ENCRYPTED MESSAGE-----";
        case CV_ARMOR_KEY:     return "-----END CRYPTOVAULT SECRET KEY-----";
        case CV_ARMOR_SHARE:   return "-----END CRYPTOVAULT KEY SHARE-----";
        case CV_ARMOR_PUBKEY:  return "-----END CRYPTOVAULT PUBLIC KEY-----";
        default:               return "-----END CRYPTOVAULT ARMORED DATA-----";
    }
}

int cv_armor_encode(cv_armor_type_t type,
                    const uint8_t *in_bin, size_t in_len,
                    char *out_str, size_t max_len) {
    if (!in_bin || !out_str || max_len == 0) return -1;

    const char *hdr = get_header(type);
    const char *ftr = get_footer(type);

    /* Rough size estimate: hdr + ftr + b64(in_len) + crc */
    size_t b64_len = ((in_len + 2) / 3) * 4;
    size_t lines = (b64_len + 63) / 64;
    size_t needed = strlen(hdr) + strlen(ftr) + b64_len + lines + 128;
    if (max_len < needed) return -2;

    int pos = snprintf(out_str, max_len, "%s\nVersion: CryptoVault 1.0\nComment: 1 MiB Base High-Assurance Cryptography\n\n", hdr);
    if (pos < 0 || (size_t)pos >= max_len) return -3;

    /* Base64 with 64-char line wrapping */
    size_t line_chars = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t octet_a = in_bin[i];
        uint32_t octet_b = (i + 1 < in_len) ? in_bin[i + 1] : 0;
        uint32_t octet_c = (i + 2 < in_len) ? in_bin[i + 2] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        char c1 = B64_CHARS[(triple >> 18) & 0x3F];
        char c2 = B64_CHARS[(triple >> 12) & 0x3F];
        char c3 = (i + 1 < in_len) ? B64_CHARS[(triple >> 6) & 0x3F] : '=';
        char c4 = (i + 2 < in_len) ? B64_CHARS[triple & 0x3F] : '=';

        char chunk[5] = { c1, c2, c3, c4, 0 };
        for (int k = 0; k < 4; k++) {
            out_str[pos++] = chunk[k];
            line_chars++;
            if (line_chars == 64) {
                out_str[pos++] = '\n';
                line_chars = 0;
            }
        }
    }
    if (line_chars != 0) {
        out_str[pos++] = '\n';
    }

    /* CRC24 checksum */
    uint32_t crc = compute_crc24(in_bin, in_len);
    char crc_b64[5];
    crc_b64[0] = B64_CHARS[(crc >> 18) & 0x3F];
    crc_b64[1] = B64_CHARS[(crc >> 12) & 0x3F];
    crc_b64[2] = B64_CHARS[(crc >> 6) & 0x3F];
    crc_b64[3] = B64_CHARS[crc & 0x3F];
    crc_b64[4] = 0;

    int written = snprintf(out_str + pos, max_len - pos, "=%s\n%s\n", crc_b64, ftr);
    if (written < 0 || (size_t)(pos + written) >= max_len) return -4;

    return 0;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int cv_armor_decode(const char *in_str,
                    cv_armor_type_t *type_out,
                    uint8_t *out_bin, size_t *out_len) {
    if (!in_str || !out_bin || !out_len || *out_len == 0) return -1;

    /* Detect type */
    int valid_hdr = 0;
    cv_armor_type_t type = CV_ARMOR_MESSAGE;
    if (strstr(in_str, "-----BEGIN CRYPTOVAULT ENCRYPTED MESSAGE-----")) {
        type = CV_ARMOR_MESSAGE;
        valid_hdr = 1;
    } else if (strstr(in_str, "-----BEGIN CRYPTOVAULT SECRET KEY-----")) {
        type = CV_ARMOR_KEY;
        valid_hdr = 1;
    } else if (strstr(in_str, "-----BEGIN CRYPTOVAULT KEY SHARE-----")) {
        type = CV_ARMOR_SHARE;
        valid_hdr = 1;
    } else if (strstr(in_str, "-----BEGIN CRYPTOVAULT PUBLIC KEY-----")) {
        type = CV_ARMOR_PUBKEY;
        valid_hdr = 1;
    }
    if (!valid_hdr) return -1;
    if (type_out) *type_out = type;

    /* Verify corresponding footer exists */
    const char *ftr = get_footer(type);
    if (!strstr(in_str, ftr)) return -2;

    /* Find empty line marking body start */
    const char *body = strstr(in_str, "\n\n");
    if (!body) body = strstr(in_str, "\r\n\r\n");
    if (!body) return -3;
    while (*body == '\r' || *body == '\n') body++;

    size_t capacity = *out_len;
    size_t decoded = 0;
    uint32_t buf = 0;
    int bits = 0;
    uint32_t expected_crc = 0;
    int found_crc = 0;

    const char *p = body;
    int at_line_start = 1;

    while (*p && *p != '-') {
        if (*p == '\r' || *p == '\n') {
            at_line_start = 1;
            p++;
            continue;
        }

        if (at_line_start && *p == '=') {
            /* Checksum line found at start of line: =XXXX */
            p++;
            while (*p == ' ' || *p == '\t') p++;
            char c1 = *p ? *p++ : 0;
            char c2 = *p ? *p++ : 0;
            char c3 = *p ? *p++ : 0;
            char c4 = *p ? *p++ : 0;
            if (c1 && c2 && c3 && c4) {
                expected_crc = ((uint32_t)b64_val(c1) << 18) |
                               ((uint32_t)b64_val(c2) << 12) |
                               ((uint32_t)b64_val(c3) << 6) |
                               ((uint32_t)b64_val(c4));
                found_crc = 1;
            }
            break;
        }

        at_line_start = 0;

        if (*p == ' ' || *p == '\t') {
            p++;
            continue;
        }

        if (*p == '=') {
            /* Base64 padding character */
            p++;
            continue;
        }

        int val = b64_val(*p++);
        if (val < 0) {
            continue;
        }

        buf = (buf << 6) | (uint32_t)val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (decoded < capacity) {
                out_bin[decoded++] = (uint8_t)(buf >> bits);
            } else {
                return -3; /* Buffer overflow */
            }
        }
    }

    if (decoded == 0) {
        *out_len = 0;
        return -5; /* Empty payload */
    }

    *out_len = decoded;

    if (found_crc) {
        uint32_t calc_crc = compute_crc24(out_bin, decoded);
        if (calc_crc != expected_crc) {
            cv_memzero(out_bin, decoded);
            *out_len = 0;
            return -4; /* CRC24 Checksum failure */
        }
    }

    return 0;
}

int cv_armor_self_test(void) {
    const uint8_t test_data[] = "CryptoVault ASCII Armoring & CRC24 Self Test Str";
    char armored[512];
    uint8_t decoded[512];
    size_t decoded_len = sizeof(decoded);
    cv_armor_type_t detected_type;

    if (cv_armor_encode(CV_ARMOR_KEY, test_data, sizeof(test_data), armored, sizeof(armored)) != CV_ARMOR_SUCCESS) {
        return CV_ARMOR_ERR_SELFTEST;
    }

    if (cv_armor_decode(armored, &detected_type, decoded, &decoded_len) != CV_ARMOR_SUCCESS) {
        return CV_ARMOR_ERR_SELFTEST;
    }

    if (detected_type != CV_ARMOR_KEY || decoded_len != sizeof(test_data)) {
        return CV_ARMOR_ERR_SELFTEST;
    }

    if (cv_ct_memcmp(test_data, decoded, sizeof(test_data)) != 0) {
        return CV_ARMOR_ERR_SELFTEST;
    }

    /* CRC corruption test: tamper with base64 text */
    armored[strlen(armored) - 40] ^= 0x02;
    if (cv_armor_decode(armored, &detected_type, decoded, &decoded_len) == CV_ARMOR_SUCCESS) {
        return CV_ARMOR_ERR_SELFTEST; /* Tampered armored text must fail */
    }

    cv_memzero(armored, sizeof(armored));
    cv_memzero(decoded, sizeof(decoded));
    return CV_ARMOR_SUCCESS;
}
