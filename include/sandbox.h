/**
 * @file sandbox.h
 * @brief Zero-Trust Capability-Based Security, Sandboxing & Strict Validation.
 *
 * ============================================================================
 * CryptoVault Zero-Trust Architecture Subsystem
 * ============================================================================
 *
 * Enforces the Principle of Least Privilege (PoLP) and defense-in-depth across
 * all native C cryptographic pipelines and foreign function interfaces (FFI):
 *
 * 1. Capability-Based Permission Bitmasks:
 *    - Granular fine-grained capabilities: CV_CAP_ENCRYPT, CV_CAP_DECRYPT,
 *      CV_CAP_DERIVE_KEY, CV_CAP_EXPORT_KEY, CV_CAP_FS_ACCESS, etc.
 *    - Monotonically decreasing privileges: A worker context can voluntarily
 *      drop capabilities (e.g. dropping key export and filesystem access after
 *      loading keys), but can NEVER escalate or regain dropped capabilities.
 * 2. Cryptographic Capability Tokens (Macaroon-style):
 *    - Sandboxed worker processes must present an HMAC-authenticated capability
 *      token signed with the master session key before invoking high-assurance
 *      decryption or key unwrapping primitives.
 * 3. Strict Input & Boundary Validation:
 *    - Validates buffer pointers, alignment, allocation bounds, and rejects
 *      null, unaligned, or overlapping buffers.
 * 4. Zero Implicit Trust:
 *    - Inter-component boundaries between Python bindings and native C verify
 *      memory layout, length invariants, and capability tokens on every call.
 *
 * @version 2.4.0
 * @author CryptoVault Academic Security Group
 */

#ifndef SANDBOX_H
#define SANDBOX_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Granular Capability Permission Bitmasks */
#define CV_CAP_NONE            0x00000000U
#define CV_CAP_READ_PLAINTEXT  (1U << 0)   /* Allowed to read raw plaintext */
#define CV_CAP_WRITE_PLAINTEXT (1U << 1)   /* Allowed to write raw plaintext */
#define CV_CAP_ENCRYPT         (1U << 2)   /* Allowed to perform encryption */
#define CV_CAP_DECRYPT         (1U << 3)   /* Allowed to perform decryption */
#define CV_CAP_DERIVE_KEY      (1U << 4)   /* Allowed to run KDFs / derive keys */
#define CV_CAP_EXPORT_KEY      (1U << 5)   /* Allowed to export keys / keywraps */
#define CV_CAP_FS_ACCESS       (1U << 6)   /* Allowed to read/write filesystem */
#define CV_CAP_KEYRING_ACCESS  (1U << 7)   /* Allowed to query OS kernel keyring */
#define CV_CAP_ALL             0xFFFFFFFFU /* Full administrative capability */

/* Return Status Codes */
#define CV_SANDBOX_SUCCESS           0
#define CV_SANDBOX_ERR_PARAM        -1
#define CV_SANDBOX_ERR_PERM_DENIED  -2
#define CV_SANDBOX_ERR_TOKEN_BAD    -3
#define CV_SANDBOX_ERR_OVERFLOW     -4
#define CV_SANDBOX_ERR_NULL_PTR     -5
#define CV_SANDBOX_ERR_SELFTEST     -6

#define CV_SANDBOX_TOKEN_SIZE       32

/**
 * @brief Formal Security Policy for a Sandboxed Cryptographic Worker.
 */
typedef struct {
    uint32_t allowed_caps;                 /* Active capability bitmask */
    size_t   max_buffer_size;              /* Maximum permissible buffer in bytes */
    size_t   max_chunk_count;              /* Maximum permissible chunk count */
    bool     strict_bounds_checking;       /* Enforce strict alignment and non-overlap */
    uint8_t  token[CV_SANDBOX_TOKEN_SIZE]; /* Authenticated session capability token */
} cv_sandbox_policy_t;

/**
 * @brief Sandboxed Execution Context.
 */
typedef struct {
    cv_sandbox_policy_t policy;            /* Active security policy */
    uint64_t ops_permitted;                /* Counter of authorized operations */
    uint64_t ops_denied;                   /* Counter of rejected unauthorized attempts */
    bool     is_locked;                    /* True if capabilities permanently frozen */
} cv_sandbox_context_t;

/**
 * @brief Initialize a zero-trust sandboxed context with an initial capability set.
 *
 * @param ctx          Pointer to context structure to initialize.
 * @param initial_caps Initial capability bitmask.
 * @param max_buf_size Maximum buffer size allowed (0 defaults to 1 GiB).
 * @return CV_SANDBOX_SUCCESS on success, negative error code on failure.
 */
int cv_sandbox_init(cv_sandbox_context_t *ctx, uint32_t initial_caps, size_t max_buf_size);

/**
 * @brief Voluntarily drop one or more capabilities permanently.
 *
 * @param ctx         Active sandbox context.
 * @param caps_to_drop Bitmask of capabilities to revoke.
 * @return CV_SANDBOX_SUCCESS on success, negative error code on failure.
 */
int cv_sandbox_drop_capability(cv_sandbox_context_t *ctx, uint32_t caps_to_drop);

/**
 * @brief Check whether the context holds a specific required capability.
 *
 * @param ctx          Active sandbox context.
 * @param required_cap Single capability flag to test.
 * @return CV_SANDBOX_SUCCESS if granted, CV_SANDBOX_ERR_PERM_DENIED if denied.
 */
int cv_sandbox_check_capability(cv_sandbox_context_t *ctx, uint32_t required_cap);

/**
 * @brief Validate memory buffer bounds, alignment, and permissions before execution.
 *
 * @param ctx          Active sandbox context.
 * @param buffer       Pointer to input/output buffer.
 * @param length       Length in bytes.
 * @param required_cap Capability required for this operation.
 * @return CV_SANDBOX_SUCCESS on valid buffer and permissions, negative error code on failure.
 */
int cv_sandbox_validate_buffer(cv_sandbox_context_t *ctx, const void *buffer,
                               size_t length, uint32_t required_cap);

/**
 * @brief Mint a cryptographic capability token authorizing a specific action.
 *
 * @param session_key 32-byte session secret.
 * @param target_cap  Capability to embed in token.
 * @param token_out   Buffer to receive 32-byte authentication tag.
 * @return CV_SANDBOX_SUCCESS on success, negative error code on failure.
 */
int cv_sandbox_mint_token(const uint8_t *session_key, uint32_t target_cap, uint8_t *token_out);

/**
 * @brief Verify a cryptographic capability token presented by an external caller.
 *
 * @param session_key 32-byte session secret.
 * @param target_cap  Capability required.
 * @param token_in    32-byte token to authenticate.
 * @return CV_SANDBOX_SUCCESS if valid, CV_SANDBOX_ERR_TOKEN_BAD if invalid or tampered.
 */
int cv_sandbox_verify_token(const uint8_t *session_key, uint32_t target_cap, const uint8_t *token_in);

/**
 * @brief Lock sandbox context permanently against any further capability modification.
 *
 * @param ctx Active sandbox context.
 * @return CV_SANDBOX_SUCCESS on success.
 */
int cv_sandbox_lock(cv_sandbox_context_t *ctx);

/**
 * @brief Self-test verifying privilege dropping, rejection of unauthorized actions,
 *        and capability token authentication.
 *
 * @return CV_SANDBOX_SUCCESS on success, CV_SANDBOX_ERR_SELFTEST on failure.
 */
int cv_sandbox_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* SANDBOX_H */
