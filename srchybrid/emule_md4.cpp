/* Standalone MD4 implementation for eMule (replaces CryptoPP::Weak::MD4).
 * Derived from the RSA Data Security, Inc. MD4 Message-Digest Algorithm (RFC 1320).
 *
 * License: RSA Data Security, Inc. grants permission to copy and use this
 * software provided it is identified as the "RSA Data Security, Inc.
 * MD4 Message-Digest Algorithm" in all material referencing it.
 */
#include "StdAfx.h"
#include "emule_md4.h"
#include <string.h>

static void md4_process(emule_md4_context *ctx, const uint8_t data[64]);

#define S11  3
#define S12  7
#define S13 11
#define S14 19
#define S21  3
#define S22  5
#define S23  9
#define S24 13
#define S31  3
#define S32  9
#define S33 11
#define S34 15

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s) { (a) += F((b),(c),(d)) + (x); (a) = ROTATE_LEFT((a),(s)); }
#define GG(a, b, c, d, x, s) { (a) += G((b),(c),(d)) + (x) + 0x5A827999u; (a) = ROTATE_LEFT((a),(s)); }
#define HH(a, b, c, d, x, s) { (a) += H((b),(c),(d)) + (x) + 0x6ED9EBA1u; (a) = ROTATE_LEFT((a),(s)); }

static void md4_process(emule_md4_context *ctx, const uint8_t data[64])
{
    uint32_t a = ctx->state[0], b = ctx->state[1];
    uint32_t c = ctx->state[2], d = ctx->state[3];
    uint32_t x[16];

    for (int i = 0; i < 16; ++i)
        x[i] = (uint32_t)data[i*4] | ((uint32_t)data[i*4+1] << 8)
              | ((uint32_t)data[i*4+2] << 16) | ((uint32_t)data[i*4+3] << 24);

    /* Round 1 */
    FF(a, b, c, d, x[ 0], S11); FF(d, a, b, c, x[ 1], S12);
    FF(c, d, a, b, x[ 2], S13); FF(b, c, d, a, x[ 3], S14);
    FF(a, b, c, d, x[ 4], S11); FF(d, a, b, c, x[ 5], S12);
    FF(c, d, a, b, x[ 6], S13); FF(b, c, d, a, x[ 7], S14);
    FF(a, b, c, d, x[ 8], S11); FF(d, a, b, c, x[ 9], S12);
    FF(c, d, a, b, x[10], S13); FF(b, c, d, a, x[11], S14);
    FF(a, b, c, d, x[12], S11); FF(d, a, b, c, x[13], S12);
    FF(c, d, a, b, x[14], S13); FF(b, c, d, a, x[15], S14);

    /* Round 2 */
    GG(a, b, c, d, x[ 0], S21); GG(d, a, b, c, x[ 4], S22);
    GG(c, d, a, b, x[ 8], S23); GG(b, c, d, a, x[12], S24);
    GG(a, b, c, d, x[ 1], S21); GG(d, a, b, c, x[ 5], S22);
    GG(c, d, a, b, x[ 9], S23); GG(b, c, d, a, x[13], S24);
    GG(a, b, c, d, x[ 2], S21); GG(d, a, b, c, x[ 6], S22);
    GG(c, d, a, b, x[10], S23); GG(b, c, d, a, x[14], S24);
    GG(a, b, c, d, x[ 3], S21); GG(d, a, b, c, x[ 7], S22);
    GG(c, d, a, b, x[11], S23); GG(b, c, d, a, x[15], S24);

    /* Round 3 */
    HH(a, b, c, d, x[ 0], S31); HH(d, a, b, c, x[ 8], S32);
    HH(c, d, a, b, x[ 4], S33); HH(b, c, d, a, x[12], S34);
    HH(a, b, c, d, x[ 2], S31); HH(d, a, b, c, x[10], S32);
    HH(c, d, a, b, x[ 6], S33); HH(b, c, d, a, x[14], S34);
    HH(a, b, c, d, x[ 1], S31); HH(d, a, b, c, x[ 9], S32);
    HH(c, d, a, b, x[ 5], S33); HH(b, c, d, a, x[13], S34);
    HH(a, b, c, d, x[ 3], S31); HH(d, a, b, c, x[11], S32);
    HH(c, d, a, b, x[ 7], S33); HH(b, c, d, a, x[15], S34);

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    memset(x, 0, sizeof x);
}

void emule_md4_init(emule_md4_context *ctx)
{
    memset(ctx, 0, sizeof *ctx);
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xEFCDAB89u;
    ctx->state[2] = 0x98BADCFEu;
    ctx->state[3] = 0x10325476u;
}

void emule_md4_update(emule_md4_context *ctx, const uint8_t *input, size_t ilen)
{
    if (ilen == 0) return;

    uint32_t left = ctx->count[0] & 0x3F;
    uint32_t fill = 64 - left;

    ctx->count[0] += (uint32_t)ilen;
    if (ctx->count[0] < (uint32_t)ilen)
        ++ctx->count[1];
    ctx->count[1] += (uint32_t)(ilen >> 29);

    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        md4_process(ctx, ctx->buffer);
        input += fill;
        ilen  -= fill;
        left   = 0;
    }

    while (ilen >= 64) {
        md4_process(ctx, input);
        input += 64;
        ilen  -= 64;
    }

    if (ilen > 0)
        memcpy(ctx->buffer + left, input, ilen);
}

void emule_md4_finish(emule_md4_context *ctx, uint8_t output[16])
{
    static const uint8_t padding[64] = { 0x80 };

    uint32_t bits[2];
    bits[0] = ctx->count[0] << 3;
    bits[1] = (ctx->count[1] << 3) | (ctx->count[0] >> 29);

    uint32_t left = ctx->count[0] & 0x3F;
    uint32_t padn = (left < 56) ? (56 - left) : (120 - left);
    emule_md4_update(ctx, padding, padn);

    /* Append bit count little-endian */
    uint8_t msglen[8];
    for (int i = 0; i < 4; ++i) {
        msglen[i]   = (uint8_t)(bits[0] >> (i * 8));
        msglen[i+4] = (uint8_t)(bits[1] >> (i * 8));
    }
    emule_md4_update(ctx, msglen, 8);

    for (int i = 0; i < 4; ++i) {
        output[i*4]   = (uint8_t)(ctx->state[i]);
        output[i*4+1] = (uint8_t)(ctx->state[i] >> 8);
        output[i*4+2] = (uint8_t)(ctx->state[i] >> 16);
        output[i*4+3] = (uint8_t)(ctx->state[i] >> 24);
    }
    memset(ctx, 0, sizeof *ctx);
}
