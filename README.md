# SIMD-AES
Header Only AES-ECB|CBC|CTR implement with SIMD instruction

Header only

Easy to use

Pure SIMD implementation, high efficiency

```C++
#include <iostream>
#include "SIMDAES.h"

int main() {
	SIMDAES aes;

	if (!aes.CheckCPUCapability()) {
		std::cout << "CPU not support";
		return 1;
	}

	uint8_t key[16] = {"this is key"};
	uint8_t iv[16] = { "this is iv" };
	uint8_t buffer[1024] = { "this is buffer" };

	aes.Encrypt_CBC_128_InPlace(buffer, 1024, key, iv);
	aes.Decrypt_CBC_128_InPlace(buffer, 1024, key, iv);
}

```
