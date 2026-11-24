#pragma once
#include <stddef.h>
#include <stdint.h>

// 自行實作 SHA-256：XP SP2 的 CryptoAPI 不支援 SHA-256
void Sha256(const void* data, size_t len, uint8_t out[32]);
