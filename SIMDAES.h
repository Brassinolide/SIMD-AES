#ifndef __SIMDAES_H__
#define __SIMDAES_H__

#include <intrin.h>
#include <cstdint>

class SIMDAES {
private:
    inline __m128i _ExpandKey1(__m128i key, __m128i generatedKey) {
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        return _mm_xor_si128(key, _mm_shuffle_epi32(generatedKey, _MM_SHUFFLE(3, 3, 3, 3)));
    }

    inline __m128i _ExpandKey2(__m128i key, __m128i generatedKey) {
        generatedKey = _mm_xor_si128(generatedKey, _mm_slli_si128(generatedKey, 4));
        generatedKey = _mm_xor_si128(generatedKey, _mm_slli_si128(generatedKey, 4));
        generatedKey = _mm_xor_si128(generatedKey, _mm_slli_si128(generatedKey, 4));
        return _mm_xor_si128(generatedKey, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(key, 0), 0xaa));
    }

    void _GetRoundKeys128(uint8_t key[16], __m128i roundKey[11]) {
        roundKey[0] = _mm_load_si128((const __m128i*)(key));
        roundKey[1] = _ExpandKey1(roundKey[0], _mm_aeskeygenassist_si128(roundKey[0], 0x01));
        roundKey[2] = _ExpandKey1(roundKey[1], _mm_aeskeygenassist_si128(roundKey[1], 0x02));
        roundKey[3] = _ExpandKey1(roundKey[2], _mm_aeskeygenassist_si128(roundKey[2], 0x04));
        roundKey[4] = _ExpandKey1(roundKey[3], _mm_aeskeygenassist_si128(roundKey[3], 0x08));
        roundKey[5] = _ExpandKey1(roundKey[4], _mm_aeskeygenassist_si128(roundKey[4], 0x10));
        roundKey[6] = _ExpandKey1(roundKey[5], _mm_aeskeygenassist_si128(roundKey[5], 0x20));
        roundKey[7] = _ExpandKey1(roundKey[6], _mm_aeskeygenassist_si128(roundKey[6], 0x40));
        roundKey[8] = _ExpandKey1(roundKey[7], _mm_aeskeygenassist_si128(roundKey[7], 0x80));
        roundKey[9] = _ExpandKey1(roundKey[8], _mm_aeskeygenassist_si128(roundKey[8], 0x1B));
        roundKey[10] = _ExpandKey1(roundKey[9], _mm_aeskeygenassist_si128(roundKey[9], 0x36));
    }

    void _GetRoundKeys256(uint8_t key[32], __m128i roundKey[15]) {
        roundKey[0] = _mm_load_si128(reinterpret_cast<__m128i*>(key));
        roundKey[1] = _mm_load_si128(reinterpret_cast<__m128i*>(key + 16));
        roundKey[2] = _ExpandKey1(roundKey[0], _mm_aeskeygenassist_si128(roundKey[1], 0x01));
        roundKey[3] = _ExpandKey2(roundKey[2], roundKey[1]);
        roundKey[4] = _ExpandKey1(roundKey[2], _mm_aeskeygenassist_si128(roundKey[3], 0x02));
        roundKey[5] = _ExpandKey2(roundKey[4], roundKey[3]);
        roundKey[6] = _ExpandKey1(roundKey[4], _mm_aeskeygenassist_si128(roundKey[5], 0x04));
        roundKey[7] = _ExpandKey2(roundKey[6], roundKey[5]);
        roundKey[8] = _ExpandKey1(roundKey[6], _mm_aeskeygenassist_si128(roundKey[7], 0x08));
        roundKey[9] = _ExpandKey2(roundKey[8], roundKey[7]);
        roundKey[10] = _ExpandKey1(roundKey[8], _mm_aeskeygenassist_si128(roundKey[9], 0x10));
        roundKey[11] = _ExpandKey2(roundKey[10], roundKey[9]);
        roundKey[12] = _ExpandKey1(roundKey[10], _mm_aeskeygenassist_si128(roundKey[11], 0x20));
        roundKey[13] = _ExpandKey2(roundKey[12], roundKey[11]);
        roundKey[14] = _ExpandKey1(roundKey[12], _mm_aeskeygenassist_si128(roundKey[13], 0x40));
    }

    void _ClearRoundKeys128(__m128i roundKey[11]) {
        for (int i = 0; i < 11; i++) {
            roundKey[i] = _mm_setzero_si128();
        }
    }

    void _ClearRoundKeys256(__m128i roundKey[15]) {
        for (int i = 0; i < 15; i++) {
            roundKey[i] = _mm_setzero_si128();
        }
    }

    inline __m128i _AES_Encrypt128(__m128i plaintext, __m128i roundKey[11]) {
        plaintext = _mm_xor_si128(plaintext, roundKey[0]);

        for (int i = 1; i < 10; i++)
            plaintext = _mm_aesenc_si128(plaintext, roundKey[i]);

        return _mm_aesenclast_si128(plaintext, roundKey[10]);
    }

    inline __m128i _AES_Decrypt128(__m128i cipher, __m128i roundKey[11]) {
        cipher = _mm_xor_si128(cipher, roundKey[10]);

        for (int i = 9; i > 0; i--)
            cipher = _mm_aesdec_si128(cipher, _mm_aesimc_si128(roundKey[i]));

        return _mm_aesdeclast_si128(cipher, roundKey[0]);
    }

    inline __m128i _AES_Encrypt256(__m128i plaintext, __m128i roundKey[15]) {
        plaintext = _mm_xor_si128(plaintext, roundKey[0]);

        for (int i = 1; i < 14; i++)
            plaintext = _mm_aesenc_si128(plaintext, roundKey[i]);

        return _mm_aesenclast_si128(plaintext, roundKey[14]);
    }

    inline __m128i _AES_Decrypt256(__m128i cipher, __m128i roundKey[15]) {
        cipher = _mm_xor_si128(cipher, roundKey[14]);

        for (int i = 13; i > 0; i--)
            cipher = _mm_aesdec_si128(cipher, _mm_aesimc_si128(roundKey[i]));

        return _mm_aesdeclast_si128(cipher, roundKey[0]);
    }

    void _SecureZeroMemory(uint8_t* ptr, size_t size) {
        volatile char* vptr = (volatile char*)ptr;
        while (size) {
            *vptr = 0;
            vptr++;
            size--;
        }
    }

public:
    bool CheckCPUCapability() {
        int i[4];
        __cpuid(i, 1);
        bool AES_NI = i[2] & (1 << 25);
        bool SSE2 = i[3] & (1 << 26);
        return AES_NI && SSE2;
    }

    bool Encrypt_ECB_128_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[16], bool clearSensitiveData = false) {
        if (!buffer || !key || cbBufferSize % 16)return false;
        
        __m128i roundKey[11];
        _GetRoundKeys128(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 16);
        }
        
        for (size_t offset = 0; offset < cbBufferSize; offset += 16) {
            _mm_store_si128((__m128i*)(buffer + offset), _AES_Encrypt128(_mm_load_si128((const __m128i*)(buffer + offset)), roundKey));
        }
        _ClearRoundKeys128(roundKey);
        return true;
    }

    bool Decrypt_ECB_128_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[16], bool clearSensitiveData = false) {
        if (!buffer || !key || cbBufferSize % 16)return false;

        __m128i roundKey[11];
        _GetRoundKeys128(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 16);
        }

        for (size_t offset = 0; offset < cbBufferSize; offset += 16) {
            _mm_store_si128((__m128i*)(buffer + offset), _AES_Decrypt128(_mm_load_si128((const __m128i*)(buffer + offset)), roundKey));
        }
        _ClearRoundKeys128(roundKey);
        return true;
    }

    bool Encrypt_ECB_256_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[32], bool clearSensitiveData = false) {
        if (!buffer || !key || cbBufferSize % 16)return false;

        __m128i roundKey[15];
        _GetRoundKeys256(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 32);
        }

        for (size_t offset = 0; offset < cbBufferSize; offset += 16) {
            _mm_store_si128((__m128i*)(buffer + offset), _AES_Encrypt256(_mm_load_si128((const __m128i*)(buffer + offset)), roundKey));
        }
        _ClearRoundKeys256(roundKey);
        return true;
    }

    bool Decrypt_ECB_256_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[32], bool clearSensitiveData = false) {
        if (!buffer || !key || cbBufferSize % 16)return false;

        __m128i roundKey[15];
        _GetRoundKeys256(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 32);
        }

        for (size_t offset = 0; offset < cbBufferSize; offset += 16) {
            _mm_store_si128((__m128i*)(buffer + offset), _AES_Decrypt256(_mm_load_si128((const __m128i*)(buffer + offset)), roundKey));
        }
        _ClearRoundKeys256(roundKey);
        return true;
    }

    bool Encrypt_CBC_128_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[16], uint8_t iv[16], bool clearSensitiveData = false) {
        if (!buffer || !key || !iv || cbBufferSize % 16)return false;

        __m128i roundKey[11];
        _GetRoundKeys128(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 16);
            _SecureZeroMemory(iv, 16);
        } 

        __m128i lastCipher = _mm_load_si128((const __m128i*)iv);
        for (size_t offset = 0; offset < cbBufferSize; offset += 16) {
            lastCipher = _AES_Encrypt128(_mm_xor_si128(lastCipher, _mm_load_si128((const __m128i*)(buffer + offset))), roundKey);
            _mm_store_si128((__m128i*)(buffer + offset), lastCipher);
        }
        _ClearRoundKeys128(roundKey);
        return true;
    }

    bool Decrypt_CBC_128_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[16], uint8_t iv[16], bool clearSensitiveData = false) {
        if (!buffer || !key || !iv || cbBufferSize % 16)return false;

        __m128i roundKey[11];
        _GetRoundKeys128(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 16);
            _SecureZeroMemory(iv, 16);
        }

        __m128i lastCipher = _mm_load_si128((const __m128i*)iv);
        for (size_t offset = 0; offset < cbBufferSize; offset += 16) {
            __m128i cipher = _mm_load_si128((const __m128i*)(buffer + offset));
            _mm_store_si128((__m128i*)(buffer + offset), _mm_xor_si128(lastCipher, _AES_Decrypt128(cipher, roundKey)));
            lastCipher = cipher;
        }
        _ClearRoundKeys128(roundKey);
        return true;
    }

    bool Encrypt_CBC_256_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[32], uint8_t iv[16], bool clearSensitiveData = false) {
        if (!buffer || !key || !iv || cbBufferSize % 16)return false;

        __m128i roundKey[15];
        _GetRoundKeys256(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 32);
            _SecureZeroMemory(iv, 16);
        }

        __m128i lastCipher = _mm_load_si128((const __m128i*)iv);
        for (size_t offset = 0; offset < cbBufferSize; offset += 16) {
            lastCipher = _AES_Encrypt256(_mm_xor_si128(lastCipher, _mm_load_si128((const __m128i*)(buffer + offset))), roundKey);
            _mm_store_si128((__m128i*)(buffer + offset), lastCipher);
        }
        _ClearRoundKeys256(roundKey);
        return true;
    }

    bool Decrypt_CBC_256_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[32], uint8_t iv[16], bool clearSensitiveData = false) {
        if (!buffer || !key || !iv || cbBufferSize % 16)return false;

        __m128i roundKey[15];
        _GetRoundKeys256(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 32);
            _SecureZeroMemory(iv, 16);
        }

        __m128i lastCipher = _mm_load_si128((const __m128i*)iv);
        for (size_t offset = 0; offset < cbBufferSize; offset += 16) {
            __m128i cipher = _mm_load_si128((const __m128i*)(buffer + offset));
            _mm_store_si128((__m128i*)(buffer + offset), _mm_xor_si128(lastCipher, _AES_Decrypt256(cipher, roundKey)));
            lastCipher = cipher;
        }
        _ClearRoundKeys256(roundKey);
        return true;
    }

    bool Encrypt_CTR_128_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[16], uint8_t iv[16], bool clearSensitiveData = false) {
        if (!buffer || !key || !iv)return false;

        __m128i roundKey[11];
        _GetRoundKeys128(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 16);
            _SecureZeroMemory(iv, 16);
        }

        __m128i mask = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
        __m128i ctr = _mm_shuffle_epi8(_mm_load_si128((const __m128i*)iv), mask);
        for (size_t offset = 0; offset < cbBufferSize;) {
            size_t remaining = cbBufferSize - offset;
            if (cbBufferSize - offset >= 16) {
                _mm_store_si128((__m128i*)(buffer + offset), _mm_xor_si128(_AES_Encrypt128(_mm_shuffle_epi8(ctr, mask), roundKey), _mm_load_si128((const __m128i*)(buffer + offset))));
                offset += 16;
                ctr = _mm_add_epi64(ctr, _mm_set_epi64x(0, 1));
            }
            else {
                uint8_t temp[16] = {0};
                for (int i = 0; i < remaining; i++) temp[i] = buffer[i];
                _mm_store_si128((__m128i*)temp, _mm_xor_si128(_AES_Encrypt128(_mm_shuffle_epi8(ctr, mask), roundKey), _mm_load_si128((const __m128i*)temp)));
                for (int i = 0; i < remaining; i++) buffer[i] = temp[i];
                break;
            }
        }
        _ClearRoundKeys128(roundKey);
        return true;
    }

    bool Decrypt_CTR_128_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[16], uint8_t iv[16], bool clearSensitiveData = false) {
        return Encrypt_CTR_128_InPlace(buffer, cbBufferSize, key, iv, clearSensitiveData);
    }

    bool Encrypt_CTR_256_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[32], uint8_t iv[16], bool clearSensitiveData = false) {
        if (!buffer || !key || !iv)return false;

        __m128i roundKey[15];
        _GetRoundKeys256(key, roundKey);

        if (clearSensitiveData) {
            _SecureZeroMemory(key, 32);
            _SecureZeroMemory(iv, 16);
        }

        __m128i mask = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
        __m128i ctr = _mm_shuffle_epi8(_mm_load_si128((const __m128i*)iv), mask);
        for (size_t offset = 0; offset < cbBufferSize;) {
            size_t remaining = cbBufferSize - offset;
            if (cbBufferSize - offset >= 16) {
                _mm_store_si128((__m128i*)(buffer + offset), _mm_xor_si128(_AES_Encrypt256(_mm_shuffle_epi8(ctr, mask), roundKey), _mm_load_si128((const __m128i*)(buffer + offset))));
                offset += 16;
                ctr = _mm_add_epi64(ctr, _mm_set_epi64x(0, 1));
            }
            else {
                uint8_t temp[16] = { 0 };
                for (int i = 0; i < remaining; i++) temp[i] = buffer[i];
                _mm_store_si128((__m128i*)temp, _mm_xor_si128(_AES_Encrypt256(_mm_shuffle_epi8(ctr, mask), roundKey), _mm_load_si128((const __m128i*)temp)));
                for (int i = 0; i < remaining; i++) buffer[i] = temp[i];
                break;
            }
        }
        _ClearRoundKeys256(roundKey);
        return true;
    }

    bool Decrypt_CTR_256_InPlace(uint8_t* buffer, size_t cbBufferSize, uint8_t key[32], uint8_t iv[16], bool clearSensitiveData = false) {
        return Encrypt_CTR_256_InPlace(buffer, cbBufferSize, key, iv, clearSensitiveData);
    }
};

#endif
