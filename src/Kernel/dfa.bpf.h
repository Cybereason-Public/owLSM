#pragma once
#include "rodata_maps_related_structs.h"

int kmp_dfa_search(const struct string_utils_ctx *sctx);
int regex_dfa_search(const struct string_utils_ctx *sctx);
