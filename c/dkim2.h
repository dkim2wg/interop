#pragma once
#include "dkim2_internal.h"

dkim2_ctx_t *dkim2_ctx_new(void);
void dkim2_ctx_free(dkim2_ctx_t *ctx);
