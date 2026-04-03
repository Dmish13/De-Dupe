#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "hash_functions.h"

// Hash bytes are fixed-length digests, so memcmp is the fastest equality check.
int compare_hashes(unsigned char *a, unsigned char *b, int n) {
	return memcmp(a, b, (size_t)n) == 0;
}

typedef struct {
	unsigned char *data;
	unsigned char **hashes;
	int start;
	int end;
	int chunk_size;
} worker_args_t;

typedef struct {
	unsigned char *hash;
	size_t sig;
	int used;
} seen_entry_t;

static unsigned char *fast_calculate_sha512(unsigned char *buf, unsigned int buf_size);

static size_t next_pow2(size_t x) {
	// Open-addressing table uses power-of-two size for fast masking instead of modulo.
	size_t p = 1;
	while(p < x)
		p <<= 1;
	return p;
}

static size_t hash_bytes(const unsigned char *buf, int n) {
	// Mix first/last machine words of digest into a compact hash for table indexing.
	size_t h1 = 0;
	size_t h2 = 0;
	int w = (int)sizeof(size_t);

	if(n >= w)
		memcpy(&h1, buf, (size_t)w);
	else
		memcpy(&h1, buf, (size_t)n);

	if(n >= 2 * w)
		memcpy(&h2, buf + (size_t)(n - w), (size_t)w);
	else
		h2 = (size_t)n * (size_t)0x9E3779B97F4A7C15ULL;

	size_t h = h1 ^ (h2 + (size_t)0x9E3779B97F4A7C15ULL + (h1 << 6) + (h1 >> 2));
	h ^= h >> 33;
	h *= (size_t)0xFF51AFD7ED558CCDULL;
	h ^= h >> 33;
	return h;
}

static size_t hash_sig(const unsigned char *buf, int n) {
	// Secondary signature reduces full memcmp calls on hash-table collisions.
	size_t a = 0;
	size_t b = 0;
	int w = (int)sizeof(size_t);

	if(n >= w)
		memcpy(&a, buf, (size_t)w);
	else
		memcpy(&a, buf, (size_t)n);

	if(n >= 2 * w)
		memcpy(&b, buf + (size_t)(n - w), (size_t)w);
	else
		b = (size_t)n * (size_t)0xD6E8FEB86659FD93ULL;

	return a ^ (b + (size_t)0x9E3779B97F4A7C15ULL + (a << 6) + (a >> 2));
}

static void *worker(void *arg) {
	// Each worker hashes a disjoint contiguous range of chunks.
	worker_args_t *w = (worker_args_t *)arg;
	for(int i = w->start; i < w->end; i++) {
		w->hashes[i] = fast_calculate_sha512(
			w->data + ((size_t)i * (size_t)w->chunk_size),
			(unsigned int)w->chunk_size
		);
	}
	return NULL;
}

// Faster equivalent of calculate_sha512(): same digest semantics, lower overhead.
static unsigned char *fast_calculate_sha512(unsigned char *buf, unsigned int buf_size) {
	// 1) Digest original bytes.
	unsigned int sha_len_1 = size_sha512();
	unsigned int sha_len_2 = size_sha512();
	unsigned char d1[EVP_MAX_MD_SIZE];
	unsigned char d2[EVP_MAX_MD_SIZE];
	unsigned int counts[256] = {0};

	assert(EVP_Digest(buf, buf_size, d1, &sha_len_1, EVP_sha512(), NULL) == 1);

	// 2) Sort chunk bytes via counting sort (alphabet is fixed: 0..255).
	for(unsigned int i = 0; i < buf_size; i++)
		counts[buf[i]]++;

	unsigned int pos = 0;
	for(int v = 0; v < 256; v++) {
		unsigned int c = counts[v];
		for(unsigned int k = 0; k < c; k++)
			buf[pos++] = (unsigned char)v;
	}

	// 3) Digest sorted bytes and XOR both digests to match project hash behavior.
	assert(EVP_Digest(buf, buf_size, d2, &sha_len_2, EVP_sha512(), NULL) == 1);
	assert(sha_len_1 == sha_len_2);

	unsigned char *out = (unsigned char *)malloc(sha_len_1);
	assert(out != NULL);
	for(unsigned int i = 0; i < sha_len_1; i++)
		out[i] = d1[i] ^ d2[i];

	return out;
}

static void hash_chunks_single_thread(FILE *fp, unsigned char **hashes, int n_hashes, int chunk_size) {
	// Tiny workloads avoid thread-creation overhead by hashing sequentially.
	unsigned char *chunk = (unsigned char *)malloc((size_t)chunk_size);
	assert(chunk != NULL);
	for(int i = 0; i < n_hashes; i++) {
		size_t r = fread(chunk, 1, (size_t)chunk_size, fp);
		assert(r == (size_t)chunk_size);
		hashes[i] = fast_calculate_sha512(chunk, (unsigned int)chunk_size);
	}
	free(chunk);
}

// Function name: dedupe
// Description:   Computes a hash for each chunk of the input file, and the obtained hashes
//                to each other to determine the number of unique chunks in the file
void dedupe(char *filename, int chunk_size, char *output) {
	FILE *fp;
	unsigned char *data = NULL;
	unsigned char **hashes = NULL;
	int *mask = NULL;
	int hash_size = size_sha512(), n_hashes = 0;
	size_t data_bytes = 0;

	// Count full chunks; trailing partial chunk is intentionally ignored.
	fp = fopen(filename, "rb");
	assert(fp != NULL);
	assert(fseek(fp, 0, SEEK_END) == 0);
	long file_size = ftell(fp);
	assert(file_size >= 0);
	assert(fseek(fp, 0, SEEK_SET) == 0);
	n_hashes = (int)(file_size / chunk_size);
	data_bytes = (size_t)n_hashes * (size_t)chunk_size;

	hashes = (unsigned char **)calloc((size_t)n_hashes, sizeof(unsigned char *));
	assert(hashes != NULL || n_hashes == 0);

	if(n_hashes > 0) {
		// Use single-thread hashing only for truly small workloads.
		if(n_hashes < 8 || data_bytes < (size_t)(1U << 20)) {
			hash_chunks_single_thread(fp, hashes, n_hashes, chunk_size);
		} else {
			// Bulk-read once, then hash in parallel to minimize per-chunk I/O overhead.
			data = (unsigned char *)malloc(data_bytes);
			assert(data != NULL);
			size_t r = fread(data, 1, data_bytes, fp);
			assert(r == data_bytes);

			// Keep thread count <= 4 for the target machine and below project cap.
			int n_threads = 4;
			if(data_bytes < (size_t)(8U << 20))
				n_threads = 2;
			if(n_threads > 11)
				n_threads = 11;
			if(n_threads > n_hashes)
				n_threads = n_hashes;
			if(n_threads < 1)
				n_threads = 1;

			pthread_t *threads = (pthread_t *)malloc((size_t)n_threads * sizeof(pthread_t));
			worker_args_t *args = (worker_args_t *)malloc((size_t)n_threads * sizeof(worker_args_t));
			assert(threads != NULL);
			assert(args != NULL);

			int base = n_hashes / n_threads;
			int rem = n_hashes % n_threads;
			int start = 0;
			for(int t = 0; t < n_threads; t++) {
				int span = base + (t < rem ? 1 : 0);
				args[t].data = data;
				args[t].hashes = hashes;
				args[t].start = start;
				args[t].end = start + span;
				args[t].chunk_size = chunk_size;
				start += span;
				assert(pthread_create(&threads[t], NULL, worker, &args[t]) == 0);
			}

			for(int t = 0; t < n_threads; t++)
				assert(pthread_join(threads[t], NULL) == 0);

			free(args);
			free(threads);
		}
	}
	fclose(fp);
	free(data);

	mask = (int *)calloc((size_t)n_hashes, sizeof(int));
	assert(mask != NULL || n_hashes == 0);

	if(n_hashes > 0) {
		// For small n, O(n^2) scan is faster than building a hash table.
		if(n_hashes <= 512) {
			for(int i = 0; i < n_hashes; i++) {
				for(int j = i + 1; j < n_hashes; j++) {
					if(compare_hashes(hashes[i], hashes[j], hash_size)) {
						mask[j] = 1;
						break;
					}
				}
			}
		} else {
			// For large n, use open-addressed hash table for near-linear duplicate marking.
			size_t table_cap = next_pow2((size_t)n_hashes * 2U);
			if(table_cap < 2)
				table_cap = 2;
			seen_entry_t *table = (seen_entry_t *)calloc(table_cap, sizeof(seen_entry_t));
			assert(table != NULL);

			size_t table_mask = table_cap - 1;
			for(int i = 0; i < n_hashes; i++) {
				size_t sig = hash_sig(hashes[i], hash_size);
				size_t pos = hash_bytes(hashes[i], hash_size) & table_mask;
				int found = 0;

				while(table[pos].used) {
					if(table[pos].sig == sig && compare_hashes(table[pos].hash, hashes[i], hash_size)) {
						mask[i] = 1;
						found = 1;
						break;
					}
					pos = (pos + 1U) & table_mask;
				}

				if(!found) {
					table[pos].used = 1;
					table[pos].hash = hashes[i];
					table[pos].sig = sig;
				}
			}

			free(table);
		}
	}

	// Emit the 0/1 mask in one write call to reduce stdio overhead.
	fp = fopen(output, "w");
	assert(fp != NULL);
	char *out_buf = (char *)malloc((size_t)n_hashes + 2U);
	assert(out_buf != NULL);
	for(int i = 0; i < n_hashes; i++)
		out_buf[i] = (char)('0' + mask[i]);
	out_buf[n_hashes] = '\n';
	size_t written = fwrite(out_buf, 1, (size_t)n_hashes + 1U, fp);
	assert(written == (size_t)n_hashes + 1U);
	free(out_buf);
	fclose(fp);

	// release stuff
	free(mask);
	for(int i=0; i < n_hashes; i++)
		free(hashes[i]);
	free(hashes);
}

