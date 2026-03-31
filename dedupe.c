#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>

#include "hash_functions.h"

int compare_hashes(unsigned char *a, unsigned char *b, int n) {
	for(int i=0; i < n; i++)
		if(a[i] != b[i])
			return 0;
	return 1;
}

// Queue for producer/consumer
typedef struct {
	int idx;
	unsigned char *chunk;
} job_t;

//Queue variables
static job_t *q = NULL;
static int q_size = 0;
static int q_head = 0;
static int q_tail = 0;
static int q_count = 0;
static int producer_done = 0; //Tells if producer is done accepting jobs

//Locks for quee and condition variables
static pthread_mutex_t q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t q_not_full = PTHREAD_COND_INITIALIZER;

static unsigned char **g_hashes = NULL;
static int g_chunk_size = 0;

//Worker thread function
static void *worker(void *arg) {
	(void)arg;
	while(1) {
		//If queue is empty and there is still jobs to be processed, sleep until more jobs are available
		pthread_mutex_lock(&q_lock);
		while(q_count == 0 && !producer_done)
			pthread_cond_wait(&q_not_empty, &q_lock);

		//If queue is empty and producer is done, break the loop because there are no more jobs to process
		if(q_count == 0 && producer_done) {
			pthread_mutex_unlock(&q_lock);
			break;
		}

		//Get next job from queue and move head, decrement count and signal that the queue is not full so more jobs can come in
		job_t job = q[q_head];
		q_head = (q_head + 1) % q_size;
		q_count--;
		pthread_cond_signal(&q_not_full);
		pthread_mutex_unlock(&q_lock);

		//Calculate hash for the chunk and store it in the global hashes array and free the chunk
		g_hashes[job.idx] = calculate_sha512(job.chunk, (unsigned int)g_chunk_size);
		free(job.chunk);
	}
	return NULL;
}

// Function name: dedupe
// Description:   Computes a hash for each chunk of the input file, and the obtained hashes
//                to each other to determine the number of unique chunks in the file
void dedupe(char *filename, int chunk_size, char *output) {
	FILE *fp;
	unsigned char **hashes = NULL;
	int hash_size = size_sha512(), n_hashes = 0;

	// count full chunks first
	fp = fopen(filename, "rb");
	assert(fp != NULL);
	assert(fseek(fp, 0, SEEK_END) == 0);
	long file_size = ftell(fp);
	assert(file_size >= 0);
	assert(fseek(fp, 0, SEEK_SET) == 0);
	n_hashes = (int)(file_size / chunk_size);

	hashes = (unsigned char **)calloc((size_t)n_hashes, sizeof(unsigned char *));
	assert(hashes != NULL || n_hashes == 0);

	// globals used by workers and queue size
	g_hashes = hashes;
	g_chunk_size = chunk_size;
	q_size = 32; //[Tester, USE THIS TO TEST WITH DIFFERENT QUEUE SIZE]
	q = (job_t *)malloc((size_t)q_size * sizeof(job_t));
	assert(q != NULL);
	q_head = 0;
	q_tail = 0;
	q_count = 0;
	producer_done = 0;

	int n_threads = 4; //Number of threads to use [TESTER, USE THIS TO TEST WITH DIFFERENT NUMBER OF THREADS]
	pthread_t *threads = (pthread_t *)malloc((size_t)n_threads * sizeof(pthread_t));
	assert(threads != NULL);
	for(int i = 0; i < n_threads; i++)
		assert(pthread_create(&threads[i], NULL, worker, NULL) == 0);

	// Producer: iterate through each chunk and add it to the queue and wake up worker if needed
	for(int idx = 0; idx < n_hashes; idx++) {
		unsigned char *chunk = (unsigned char *)malloc((size_t)chunk_size);
		assert(chunk != NULL);
		size_t r = fread(chunk, sizeof(unsigned char), (size_t)chunk_size, fp);
		assert(r == (size_t)chunk_size);

		//Lock the queue and wait until the queue is not full
		pthread_mutex_lock(&q_lock); 
		while(q_count == q_size)
			pthread_cond_wait(&q_not_full, &q_lock);
		//Set values in queue and increment tail and count
		q[q_tail].idx = idx; 
		q[q_tail].chunk = chunk;
		q_tail = (q_tail + 1) % q_size;
		q_count++;
		pthread_cond_signal(&q_not_empty);
		pthread_mutex_unlock(&q_lock);
	}
	fclose(fp);

	//Say produce is done and wake up all workers
	pthread_mutex_lock(&q_lock);
	producer_done = 1;
	pthread_cond_broadcast(&q_not_empty);
	pthread_mutex_unlock(&q_lock);

	//Join all threads and free threads and queue
	for(int i = 0; i < n_threads; i++)
		assert(pthread_join(threads[i], NULL) == 0);
	free(threads);
	free(q);
	q = NULL;

	int mask[n_hashes];
	for(int i=0; i < n_hashes; i++)
		mask[i] = 0;
	for(int i=0; i < n_hashes; i++)
		for(int j=i+1; j < n_hashes; j++)
			if(compare_hashes(hashes[i], hashes[j], hash_size)) {	
				mask[j] = 1;
				break;
			}

	// print results
	fp = fopen(output, "w");
	assert(fp != NULL);
	for(int i=0; i < n_hashes; i++)
		fprintf(fp, "%d", mask[i]);
	fprintf(fp, "\n");
	fclose(fp);

	// release stuff
	for(int i=0; i < n_hashes; i++)
		free(hashes[i]);
	free(hashes);
}

