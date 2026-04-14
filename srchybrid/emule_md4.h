#pragma once
/* Standalone MD4 implementation for eMule (replaces CryptoPP::Weak::MD4).
 * Derived from the RSA Data Security, Inc. MD4 Message-Digest Algorithm (RFC 1320).
 * This file has no external dependencies.
 */
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t  buffer[64];
} emule_md4_context;

void emule_md4_init(emule_md4_context *ctx);
void emule_md4_update(emule_md4_context *ctx, const uint8_t *input, size_t ilen);
void emule_md4_finish(emule_md4_context *ctx, uint8_t output[16]);
