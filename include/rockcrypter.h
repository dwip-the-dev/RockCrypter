#ifndef ROCKCRYPTER_H
#define ROCKCRYPTER_H

#include "rock_mem.h"
#include "rock_entropy.h"
#include "rock_sponge.h"
#include "rock_core.h"
#include "rock_kdf.h"
#include "rock_mac.h"
#include "rock_aead.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROCKCRYPTER_VERSION_MAJOR 1
#define ROCKCRYPTER_VERSION_MINOR 0
#define ROCKCRYPTER_VERSION_PATCH 0
#define ROCKCRYPTER_VERSION_STRING "1.0.0"

/**
 * Get human-readable description of error code.
 */
const char *rock_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* ROCKCRYPTER_H */
