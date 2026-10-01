/**
 * @file sandbox.c
 * @brief Implementation of Zero-Trust Capability-Based Sandboxing & Boundary Validation.
 *
 * ============================================================================
 * CryptoVault Zero-Trust Security Architecture
 * ============================================================================
 *
 * Enforces strict capability validation, monotonic privilege de-escalation,
 * buffer bounds checking, and tokenized authorization for foreign-caller interfaces.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#include "sandbox.h"
#include "mac.h"
#include "mem.h"
#include <string.h>

#define CV_SANDBOX_DEFAULT_MAX_BUF (1024ULL * 1024ULL * 1024ULL) /* 1 GiB */

int cv_sandbox_init(cv_sandbox_context_t *ctx, uint32_t initial_caps, size_t max_buf_size) {
    if (!ctx) {
        return CV_SANDBOX_ERR_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->policy.allowed_caps = initial_caps;
    ctx->policy.max_buffer_size = (max_buf_size > 0) ? max_buf_size : CV_SANDBOX_DEFAULT_MAX_BUF;
    ctx->policy.max_chunk_count = 1000000;
    ctx->policy.strict_bounds_checking = true;
    ctx->ops_permitted = 0;
    ctx->ops_denied = 0;
    ctx->is_locked = false;

    return CV_SANDBOX_SUCCESS;
}

int cv_sandbox_drop_capability(cv_sandbox_context_t *ctx, uint32_t caps_to_drop) {
    if (!ctx) {
        return CV_SANDBOX_ERR_PARAM;
    }

    /* Monotonic de-escalation: Once dropped, capabilities can never be restored */
    ctx->policy.allowed_caps &= ~caps_to_drop;
    return CV_SANDBOX_SUCCESS;
}

int cv_sandbox_check_capability(cv_sandbox_context_t *ctx, uint32_t required_cap) {
    if (!ctx) {
        return CV_SANDBOX_ERR_PARAM;
    }

    if ((ctx->policy.allowed_caps & required_cap) == required_cap) {
        ctx->ops_permitted++;
        return CV_SANDBOX_SUCCESS;
    }

    ctx->ops_denied++;
    return CV_SANDBOX_ERR_PERM_DENIED;
}

int cv_sandbox_validate_buffer(cv_sandbox_context_t *ctx, const void *buffer,
                               size_t length, uint32_t required_cap) {
    if (!ctx) {
        return CV_SANDBOX_ERR_PARAM;
    }

    /* Check required capability first */
    int cap_ret = cv_sandbox_check_capability(ctx, required_cap);
    if (cap_ret != CV_SANDBOX_SUCCESS) {
        return cap_ret;
    }

    /* Reject null pointer if length > 0 */
    if (!buffer && length > 0) {
        return CV_SANDBOX_ERR_NULL_PTR;
    }

    /* Strict upper bound check to prevent buffer overflow attacks */
    if (length > ctx->policy.max_buffer_size) {
        return CV_SANDBOX_ERR_OVERFLOW;
    }

    return CV_SANDBOX_SUCCESS;
}

int cv_sandbox_mint_token(const uint8_t *session_key, uint32_t target_cap, uint8_t *token_out) {
    if (!session_key || !token_out) {
        return CV_SANDBOX_ERR_PARAM;
    }

    /* Message format: "CV_CAP_AUTH_TOKEN_V1" || uint32 target_cap */
    static const char PREFIX[] = "CRYPTOVAULT_CAPABILITY_AUTH_TOKEN_V1:";
    size_t prefix_len = sizeof(PREFIX) - 1;
    size_t msg_len = prefix_len + 4;
    uint8_t msg[64];
    memcpy(msg, PREFIX, prefix_len);

    uint8_t *cap_ptr = msg + prefix_len;
    cap_ptr[0] = (uint8_t)(target_cap & 0xFF);
    cap_ptr[1] = (uint8_t)((target_cap >> 8) & 0xFF);
    cap_ptr[2] = (uint8_t)((target_cap >> 16) & 0xFF);
    cap_ptr[3] = (uint8_t)((target_cap >> 24) & 0xFF);

    cv_mac_ctx_t mac_ctx;
    cv_mac_init(&mac_ctx, session_key);
    cv_mac_update(&mac_ctx, msg, msg_len);
    cv_mac_final(&mac_ctx, token_out);

    cv_mem_zero(&mac_ctx, sizeof(mac_ctx));
    cv_mem_zero(msg, sizeof(msg));
    return CV_SANDBOX_SUCCESS;
}

int cv_sandbox_verify_token(const uint8_t *session_key, uint32_t target_cap, const uint8_t *token_in) {
    if (!session_key || !token_in) {
        return CV_SANDBOX_ERR_PARAM;
    }

    uint8_t expected[CV_SANDBOX_TOKEN_SIZE];
    int ret = cv_sandbox_mint_token(session_key, target_cap, expected);
    if (ret != CV_SANDBOX_SUCCESS) {
        return ret;
    }

    int match = cv_mem_equal(expected, token_in, CV_SANDBOX_TOKEN_SIZE);
    cv_mem_zero(expected, sizeof(expected));

    return (match == 1) ? CV_SANDBOX_SUCCESS : CV_SANDBOX_ERR_TOKEN_BAD;
}

int cv_sandbox_lock(cv_sandbox_context_t *ctx) {
    if (!ctx) {
        return CV_SANDBOX_ERR_PARAM;
    }
    ctx->is_locked = true;
    return CV_SANDBOX_SUCCESS;
}

int cv_sandbox_self_test(void) {
    cv_sandbox_context_t ctx;
    uint32_t caps = CV_CAP_ENCRYPT | CV_CAP_DECRYPT | CV_CAP_DERIVE_KEY;

    if (cv_sandbox_init(&ctx, caps, 1024 * 1024) != CV_SANDBOX_SUCCESS) {
        return CV_SANDBOX_ERR_SELFTEST;
    }

    /* 1. Verify permitted capability check */
    if (cv_sandbox_check_capability(&ctx, CV_CAP_ENCRYPT) != CV_SANDBOX_SUCCESS) {
        return CV_SANDBOX_ERR_SELFTEST;
    }

    /* 2. Verify non-granted capability is denied */
    if (cv_sandbox_check_capability(&ctx, CV_CAP_FS_ACCESS) != CV_SANDBOX_ERR_PERM_DENIED) {
        return CV_SANDBOX_ERR_SELFTEST;
    }

    /* 3. Drop decrypt capability and verify revocation */
    if (cv_sandbox_drop_capability(&ctx, CV_CAP_DECRYPT) != CV_SANDBOX_SUCCESS) {
        return CV_SANDBOX_ERR_SELFTEST;
    }
    if (cv_sandbox_check_capability(&ctx, CV_CAP_DECRYPT) != CV_SANDBOX_ERR_PERM_DENIED) {
        return CV_SANDBOX_ERR_SELFTEST;
    }

    /* 4. Validate buffer limits */
    uint8_t dummy[16];
    if (cv_sandbox_validate_buffer(&ctx, dummy, 16, CV_CAP_ENCRYPT) != CV_SANDBOX_SUCCESS) {
        return CV_SANDBOX_ERR_SELFTEST;
    }
    /* Buffer size exceeding max limit */
    if (cv_sandbox_validate_buffer(&ctx, dummy, 2 * 1024 * 1024, CV_CAP_ENCRYPT) != CV_SANDBOX_ERR_OVERFLOW) {
        return CV_SANDBOX_ERR_SELFTEST;
    }
    /* Null buffer with non-zero length */
    if (cv_sandbox_validate_buffer(&ctx, NULL, 64, CV_CAP_ENCRYPT) != CV_SANDBOX_ERR_NULL_PTR) {
        return CV_SANDBOX_ERR_SELFTEST;
    }

    /* 5. Mint and verify cryptographic token */
    uint8_t secret[32] = {0xAB};
    uint8_t token[CV_SANDBOX_TOKEN_SIZE];
    if (cv_sandbox_mint_token(secret, CV_CAP_DERIVE_KEY, token) != CV_SANDBOX_SUCCESS) {
        return CV_SANDBOX_ERR_SELFTEST;
    }
    if (cv_sandbox_verify_token(secret, CV_CAP_DERIVE_KEY, token) != CV_SANDBOX_SUCCESS) {
        return CV_SANDBOX_ERR_SELFTEST;
    }

    /* Tampered token must fail */
    token[0] ^= 0x01;
    if (cv_sandbox_verify_token(secret, CV_CAP_DERIVE_KEY, token) != CV_SANDBOX_ERR_TOKEN_BAD) {
        return CV_SANDBOX_ERR_SELFTEST;
    }

    return CV_SANDBOX_SUCCESS;
}
