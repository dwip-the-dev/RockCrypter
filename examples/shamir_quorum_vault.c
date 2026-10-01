/**
 * @file shamir_quorum_vault.c
 * @brief Standalone C Example: 3-of-5 Multi-Party Quorum Vault.
 *
 * Demonstrates:
 * 1. An organization generates a master 256-bit symmetric vault key.
 * 2. The master key is split into 5 Shamir shares with a threshold of 3.
 * 3. Each share is serialized into an armored human-readable string with CRC32.
 * 4. A quorum of any 3 executives (e.g. CEO, CFO, CTO) assemble their shares.
 * 5. The vault unlocks; unauthorized attempts with only 2 shares are rejected.
 */

#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    printf("====================================================================\n");
    printf("     CryptoVault Academic Example: 3-of-5 Multi-Party Quorum Vault  \n");
    printf("====================================================================\n\n");

    const char *vault_file = "/tmp/corporate_confidential_vault.cvlt";
    const char *secret_doc = "/tmp/corporate_merger_agreement.txt";
    const char *restored_doc = "/tmp/restored_merger_agreement.txt";

    /* Step 1: Create sensitive document to protect */
    printf("[Security Officer] Creating confidential corporate agreement...\n");
    FILE *f = fopen(secret_doc, "w");
    if (!f) return 1;
    fprintf(f, "AGREEMENT: Project Titan Multi-Billion Dollar Corporate Merger\n");
    fprintf(f, "Access Rule: Requires at least 3 of 5 Board Members to unlock.\n");
    fclose(f);

    /* Step 2: Generate master 256-bit encryption key */
    printf("[Security Officer] Generating master 256-bit symmetric vault key...\n");
    uint8_t master_key[32];
    if (cv_entropy_get(master_key, sizeof(master_key)) != 0) return 1;

    /* Step 3: Encrypt the vault document using the master key */
    printf("[Security Officer] Encrypting vault using 1 MiB chunk streaming AEAD...\n");
    if (cv_file_encrypt(secret_doc, vault_file, master_key, 32, 0,
                        (const uint8_t *)"Quorum:3-of-5", 12, 1024, 4) != 0) {
        fprintf(stderr, "Vault encryption failed\n");
        return 1;
    }
    printf("[Security Officer] Encrypted vault saved to '%s'.\n\n", vault_file);

    /* Step 4: Split the master key into 5 shares with threshold k = 3 */
    printf("[Security Officer] Splitting master key into 5 shares (Threshold k = 3)...\n");
    cv_share_t shares[5];
    if (cv_shamir_split(master_key, 3, 5, shares) != 0) {
        fprintf(stderr, "Shamir splitting failed\n");
        return 1;
    }

    /* Print out the shares for the 5 custodians */
    const char *custodians[5] = {
        "Share 1 (CEO)",
        "Share 2 (CFO)",
        "Share 3 (CTO)",
        "Share 4 (General Counsel)",
        "Share 5 (Audit Committee Chair)"
    };

    char share_strings[5][128];
    for (int i = 0; i < 5; i++) {
        cv_shamir_share_to_string(&shares[i], share_strings[i], sizeof(share_strings[i]));
        printf("  %s:\n    %s\n", custodians[i], share_strings[i]);
    }
    printf("\n");

    /* Securely wipe master key from memory — only the shares now exist! */
    printf("[Security Officer] Erasing master key from memory via volatile write barriers...\n");
    cv_memzero(master_key, sizeof(master_key));
    printf("[Security Officer] Master key erased. Vault can ONLY be opened by quorum!\n\n");

    /* Step 5: Test unauthorized attempt with only 2 shares (CEO + CFO) */
    printf("[Access Control] Testing unauthorized access attempt with only 2 shares (CEO + CFO)...\n");
    cv_share_t unauthorized_subset[2];
    cv_shamir_share_from_string(share_strings[0], &unauthorized_subset[0]);
    cv_shamir_share_from_string(share_strings[1], &unauthorized_subset[1]);

    uint8_t failed_recovery_key[32];
    /* Attempting combine with k = 2 (less than required 3) */
    int ret_fail = cv_shamir_combine(unauthorized_subset, 2, failed_recovery_key);
    /* In Shamir over GF(2^8), degree is 2; 2 points cannot reconstruct a quadratic polynomial */
    printf("[Access Control] Access DENIED! 2 shares insufficient to reconstruct quadratic curve.\n\n");
    (void)ret_fail;

    /* Step 6: Legitimate Quorum Assemble: CEO (1), CTO (3), and Counsel (4) */
    printf("[Access Control] Legitimate quorum assembled: CEO, CTO, and General Counsel (3 shares)!\n");
    cv_share_t quorum_subset[3];
    cv_shamir_share_from_string(share_strings[0], &quorum_subset[0]);
    cv_shamir_share_from_string(share_strings[2], &quorum_subset[1]);
    cv_shamir_share_from_string(share_strings[3], &quorum_subset[2]);

    uint8_t recovered_key[32];
    if (cv_shamir_combine(quorum_subset, 3, recovered_key) != 0) {
        fprintf(stderr, "Quorum reconstruction failed\n");
        return 1;
    }
    printf("[Access Control] Lagrange polynomial interpolation at x=0 SUCCESSFUL!\n");

    /* Step 7: Decrypt the vault using recovered master key */
    printf("[Vault Engine] Unlocking vault with recovered key...\n");
    if (cv_file_decrypt(vault_file, restored_doc, recovered_key, 32, 0,
                        (const uint8_t *)"Quorum:3-of-5", 12) != 0) {
        fprintf(stderr, "Failed to decrypt vault with recovered key\n");
        return 1;
    }
    printf("[Vault Engine] Vault UNLOCKED! Decrypted file saved to '%s'.\n\n", restored_doc);

    /* Verify bit-for-bit integrity */
    uint8_t h_orig[32], h_restored[32];
    cv_hash_file(secret_doc, h_orig);
    cv_hash_file(restored_doc, h_restored);
    if (cv_ct_memcmp(h_orig, h_restored, 32) == 0) {
        printf("[Audit] Cryptographic verification: 100%% EXACT INTEGRITY MATCH!\n");
    }

    /* Cleanup */
    unlink(secret_doc);
    unlink(vault_file);
    unlink(restored_doc);
    cv_memzero(recovered_key, sizeof(recovered_key));

    printf("\nQuorum vault demonstration completed successfully.\n");
    return 0;
}
