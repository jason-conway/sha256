# `sha256`: A straightforward embeddable SHA-256 implementation

# Installation:

Copy both [sha256.c](sha256.c) and [sha256.h](sha256.h) into your project and include the header where needed.

# Usage:

The opaque `sha256_t` type is used to maintain digest contexts.

Contexts are initialized using
```C
void sha256_init(sha256_t *ctx);
```
Once initialized, append data to the internal `sha256_t` context with
```C
void sha256_append(sha256_t *ctx, const void *src, size_t len);
```
where `src` points to `len` bytes to be hashed.
The final message digest can be computed with
```C
void sha256_finish(sha256_t *ctx, void *dst);
```
where `dst` points to your 32-byte destination.

See [sha256.h](sha256.h) for additional API reference.
