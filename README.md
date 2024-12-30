# SIMD-AES
Header Only AES-ECB|CBC|CTR implement with SIMD instruction

```C++
#include "SIMDAES.h"

int main() {
	uint8_t key[16] = {"this is key"};
	uint8_t iv[16] = { "this is iv" };
	uint8_t buffer[1024] = { "this is buffer" };

	SIMDAES aes;
	aes.Encrypt_CBC_128_InPlace(buffer, 1024, key, iv);
	aes.Decrypt_CBC_128_InPlace(buffer, 1024, key, iv);
}
```
