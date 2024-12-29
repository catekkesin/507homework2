#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include <stdio.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

static unsigned char *hex_to_bytes(const char *hex, size_t *out_len)
{
  size_t hex_len = strlen(hex);
  if (hex_len % 2 != 0)
  {
    return NULL;
  }
  *out_len = hex_len / 2;

  unsigned char *bytes = (unsigned char *)malloc(*out_len);
  if (!bytes)
    return NULL;

  for (size_t i = 0; i < *out_len; i++)
  {
    sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
  }
  return bytes;
}

static unsigned char *pkcs7_pad(const unsigned char *data, size_t len, size_t *newLen)
{
  const size_t blockSize = 8;
  size_t remainder = len % blockSize;
  size_t padLen = (remainder == 0) ? blockSize : (blockSize - remainder);

  *newLen = len + padLen;
  unsigned char *padded = (unsigned char *)malloc(*newLen);
  if (!padded)
    return NULL;

  memcpy(padded, data, len);
  memset(padded + len, (int)padLen, padLen);
  return padded;
}

static size_t pkcs7_unpad(unsigned char *data, size_t len)
{
  if (len == 0)
    return 0;

  unsigned char padByte = data[len - 1];
  if (padByte == 0 || padByte > 8)
  {
    return len;
  }
  return len - padByte;
}

static const int IP_Table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

static const int FP_Table[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

static const int E_Table[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

static const unsigned char S_Box[8][64] = {
    /* S1 */
    {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    /* S2 */
    {
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    /* S3 */
    {
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    /* S4 */
    {
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    /* S5 */
    {
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    /* S6 */
    {
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    /* S7 */
    {
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    /* S8 */
    {
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

static const int P_Table[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

static const int PC1_Table[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

static const int PC2_Table[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

static const int LeftShifts[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

static int get_bit64(uint64_t val, int index)
{
  int shift = 64 - index;
  return (val >> shift) & 1;
}

static void set_bit64(uint64_t *val, int index, int bit)
{
  int shift = 64 - index;
  if (bit)
    *val |= (1ULL << shift);
  else
    *val &= ~(1ULL << shift);
}

static uint32_t rotate_left_28(uint32_t val, int shift)
{
  val &= 0x0FFFFFFF;
  return ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
}

uint64_t generate_iv()
{
  uint64_t iv = 0;

#ifdef _WIN32
  // Windows implementation
  HCRYPTPROV hCryptProv;

  if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
  {
    fprintf(stderr, "CryptAcquireContext failed: %lu\n", GetLastError());
    return 0;
  }

  if (!CryptGenRandom(hCryptProv, sizeof(iv), (BYTE *)&iv))
  {
    fprintf(stderr, "CryptGenRandom failed: %lu\n", GetLastError());
    CryptReleaseContext(hCryptProv, 0);
    return 0;
  }

  CryptReleaseContext(hCryptProv, 0);
#else
  // Unix/Linux implementation
  int fd = open("/dev/urandom", O_RDONLY);

  if (fd < 0)
  {
    perror("Failed to open /dev/urandom");
    return 0;
  }

  ssize_t result = read(fd, &iv, sizeof(iv));

  if (result != sizeof(iv))
  {
    perror("Failed to read from /dev/urandom");
    close(fd);
    return 0;
  }

  close(fd);
#endif

  return iv;
}

static void des_key_schedule(uint64_t key, uint64_t subkeys[16])
{
  uint64_t perm56 = 0;
  for (int i = 0; i < 56; i++)
  {
    int bit = get_bit64(key, PC1_Table[i]);
    if (bit)
      perm56 |= (1ULL << (55 - i));
  }

  uint32_t C = (perm56 >> 28) & 0x0FFFFFFF;
  uint32_t D = perm56 & 0x0FFFFFFF;

  for (int round = 0; round < 16; round++)
  {
    C = rotate_left_28(C, LeftShifts[round]);
    D = rotate_left_28(D, LeftShifts[round]);

    uint64_t CD = ((uint64_t)C << 28) | (uint64_t)D;

    uint64_t k_i = 0;
    for (int j = 0; j < 48; j++)
    {
      int bit = (CD >> (56 - PC2_Table[j])) & 1;
      if (bit)
        k_i |= (1ULL << (47 - j));
    }
    subkeys[round] = k_i;
  }
}

static uint32_t f_function(uint32_t R, uint64_t subkey)
{
  uint64_t E = 0;
  for (int i = 0; i < 48; i++)
  {
    int bit = (R >> (32 - E_Table[i])) & 1;
    if (bit)
      E |= (1ULL << (47 - i));
  }

  E ^= subkey;

  uint32_t S_out = 0;
  for (int i = 0; i < 8; i++)
  {
    uint8_t chunk = (E >> (6 * (7 - i))) & 0x3F;
    int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
    int col = (chunk >> 1) & 0x0F;

    uint8_t s_val = S_Box[i][row * 16 + col];
    S_out = (S_out << 4) | (s_val & 0x0F);
  }

  uint32_t f_res = 0;
  for (int i = 0; i < 32; i++)
  {
    int bit = (S_out >> (32 - P_Table[i])) & 1;
    f_res = (f_res << 1) | bit;
  }

  return f_res;
}

static void print_round_info(int roundNum, uint64_t LR, uint64_t roundKey)
{
  roundKey &= 0xFFFFFFFFFFFFULL;
  printf("%2d  %016" PRIx64 "  %012" PRIx64 "\n",
         roundNum, LR, roundKey);
}

static uint64_t des_encrypt_block_with_print(uint64_t block,
                                             uint64_t subkeys[16])
{
  uint64_t perm_block = 0;
  for (int i = 0; i < 64; i++)
  {
    int bit = get_bit64(block, IP_Table[i]);
    set_bit64(&perm_block, i + 1, bit);
  }

  uint32_t L = (uint32_t)(perm_block >> 32);
  uint32_t R = (uint32_t)(perm_block & 0xFFFFFFFF);

  for (int round = 0; round < 16; round++)
  {
    uint32_t temp = R;
    uint32_t f_res = f_function(R, subkeys[round]);
    R = L ^ f_res;
    L = temp;

    uint64_t LR = ((uint64_t)R << 32) | (uint64_t)L;
    print_round_info(round + 1, LR, subkeys[round]);
  }

  uint64_t preoutput = ((uint64_t)R << 32) | L;

  uint64_t out_block = 0;
  for (int i = 0; i < 64; i++)
  {
    int bit = get_bit64(preoutput, FP_Table[i]);
    set_bit64(&out_block, i + 1, bit);
  }

  return out_block;
}

static void des_encrypt_cbc_with_print(const unsigned char *in,
                                       unsigned char *out,
                                       size_t len,
                                       uint64_t key,
                                       uint64_t iv)
{
  uint64_t subkeys[16];
  des_key_schedule(key, subkeys);

  size_t blockCount = len / 8;

  for (size_t i = 0; i < blockCount; i++)
  {
    uint64_t block = 0;
    memcpy(&block, in + i * 8, 8);

    block ^= iv;

    printf("\n=== Encrypting Block %zu ===\n", i + 1);
    printf("Round  RoundOutput         RoundKey\n");
    printf("------------------------------------\n");

    uint64_t encrypted = des_encrypt_block_with_print(block, subkeys);

    memcpy(out + i * 8, &encrypted, 8);

    iv = encrypted;
  }
}

static void des_decrypt_cbc(const unsigned char *in,
                            unsigned char *out,
                            size_t len,
                            uint64_t key,
                            uint64_t iv)
{
  uint64_t subkeys[16];
  des_key_schedule(key, subkeys);

  size_t blockCount = len / 8;
  for (size_t i = 0; i < blockCount; i++)
  {
    uint64_t cblock = 0;
    memcpy(&cblock, in + i * 8, 8);

    uint64_t decrypted = 0;

    extern uint64_t des_crypt_block(uint64_t block,
                                    uint64_t subkeys[16],
                                    int encrypt);
    decrypted = des_crypt_block(cblock, subkeys, 0);

    decrypted ^= iv;

    memcpy(out + i * 8, &decrypted, 8);

    iv = cblock;
  }
}

uint64_t des_crypt_block(uint64_t block, uint64_t subkeys[16], int encrypt)
{

  uint64_t perm_block = 0;
  for (int i = 0; i < 64; i++)
  {
    int bit = get_bit64(block, IP_Table[i]);
    set_bit64(&perm_block, i + 1, bit);
  }
  uint32_t L = (uint32_t)(perm_block >> 32);
  uint32_t R = (uint32_t)(perm_block & 0xFFFFFFFF);

  for (int round = 0; round < 16; round++)
  {
    int idx = encrypt ? round : (15 - round);
    uint32_t temp = R;
    uint32_t f_res = f_function(R, subkeys[idx]);
    R = L ^ f_res;
    L = temp;
  }

  uint64_t preoutput = ((uint64_t)R << 32) | L;

  uint64_t out_block = 0;
  for (int i = 0; i < 64; i++)
  {
    int bit = get_bit64(preoutput, FP_Table[i]);
    set_bit64(&out_block, i + 1, bit);
  }
  return out_block;
}

int main(void)
{

  const char *hexInput = "43656D616C20417264612054656B6B6573696E";
  uint64_t key = 0x0123456789ABCDEFULL;
  uint64_t iv = generate_iv();

  // hex to bytes
  size_t inputLen = 0;
  unsigned char *inputBytes = hex_to_bytes(hexInput, &inputLen);
  if (!inputBytes)
  {
    fprintf(stderr, "Error: Invalid hex input.\n");
    return 1;
  }
  printf("Plaintext (hex): %s\n", hexInput);
  printf("Plaintext length: %zu bytes\n", inputLen);

  // paddng
  size_t paddedLen = 0;
  unsigned char *padded = pkcs7_pad(inputBytes, inputLen, &paddedLen);
  if (!padded)
  {
    free(inputBytes);
    fprintf(stderr, "Error: pkcs7_pad failed.\n");
    return 1;
  }

  // enc
  unsigned char *ciphertext = (unsigned char *)malloc(paddedLen);
  if (!ciphertext)
  {
    free(inputBytes);
    free(padded);
    fprintf(stderr, "Error: malloc failed for ciphertext\n");
    return 1;
  }

  // print
  des_encrypt_cbc_with_print(padded, ciphertext, paddedLen, key, iv);

  // final print
  printf("\nFinal Ciphertext (hex): ");
  for (size_t i = 0; i < paddedLen; i++)
  {
    printf("%02X", ciphertext[i]);
  }
  printf("\n");

  // dec
  unsigned char *decrypted = (unsigned char *)malloc(paddedLen);
  if (!decrypted)
  {
    free(inputBytes);
    free(padded);
    free(ciphertext);
    fprintf(stderr, "Error: malloc failed for decrypted\n");
    return 1;
  }

  des_decrypt_cbc(ciphertext, decrypted, paddedLen, key, iv);

  // unpad
  size_t unpaddedLen = pkcs7_unpad(decrypted, paddedLen);

  // final dec
  printf("Decrypted (hex): ");
  for (size_t i = 0; i < unpaddedLen; i++)
  {
    printf("%02X", decrypted[i]);
  }
  printf("\n");

  // clean
  free(inputBytes);
  free(padded);
  free(ciphertext);
  free(decrypted);

  return 0;
}
