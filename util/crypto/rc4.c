void ksa(unsigned char *state, unsigned char *key, int keylen) {
   int i, j = 0, t;
   for (i = 0; i < 256; ++i)
      state[i] = i;
   for (i = 0; i < 256; ++i) {
      j = (j + state[i] + key[i % keylen]) % 256;
      t = state[i];
      state[i] = state[j];
      state[j] = t;
   }
}

void rc4(unsigned char *state, unsigned char *data, int len) {
   int i = 0, j = 0, x, t;
   for (x = 0; x < len; ++x)  {
      i = (i + 1) % 256;
      j = (j + state[i]) % 256;
      t = state[i];
      state[i] = state[j];
      state[j] = t;
      data[x] ^= state[(state[i] + state[j]) % 256];
   }
}
