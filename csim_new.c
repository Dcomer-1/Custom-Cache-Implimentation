/*
FOR UNIQUE CACHE 
GROUP MEMBERS: 
#FILL IN

LOCATION: Rutgers University
CLASS: CS211 Computer Architecture
SESSION: Fall 2024
PROFESSOR: Dr. Tina Burns

DESCRIPTION:


NOTES:
*/
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <time.h>

// Memory Address
typedef unsigned long long int mem_addr_t;

// Enhanced Cache Line Structure
typedef struct cache_line {
    char valid;           // Valid bit
    mem_addr_t tag;       // Tag for the memory address
    time_t last_access;   // Timestamp of last access
    unsigned int access_count;  // Number of times this line has been accessed
    unsigned char priority;     // Dynamic priority for eviction
    char dirty;           // Dirty bit to track modifications
} cache_line_t;

typedef cache_line_t* cache_set_t;
typedef cache_set_t* cache_t;

// Global command line args
int verbosity = 0; // print trace if set 
int s = 0; // set index bits
int b = 0; // block offset bits
int E = 0; // associativity
char* trace_file = NULL;

int S; // number of sets 
int B; // block size (bytes)

// Counters used to record cache statistics
int miss_count = 0;
int hit_count = 0;
int eviction_count = 0;

// The cache we are simulating
cache_t cache;  
mem_addr_t set_index_mask;


 //This function should Allocate memory and initialize cache lines with enhanced properties

void initCache()
{
    int i, j;
    cache = (cache_set_t*) malloc(sizeof(cache_set_t) * S);
    for (i = 0; i < S; i++) {
        cache[i] = (cache_line_t*) malloc(sizeof(cache_line_t) * E);
        for (j = 0; j < E; j++) {
            // Enhanced initialization
            cache[i][j].valid = 0;
            cache[i][j].tag = 0;
            cache[i][j].last_access = 0;
            cache[i][j].access_count = 0;
            cache[i][j].priority = 0;
            cache[i][j].dirty = 0;
        }
    }

    // set index mask for fast access
    set_index_mask = (mem_addr_t) (pow(2, s) - 1);
}


void freeCache()
{
    int i;
    for (i = 0; i < S; i++) {
        free(cache[i]);
    }
    free(cache);
}

/* 
 * 
 * Eviction based on access count, time and priority
 * Should favor less frequently used lines
 * High priority lines should stay longer
 * Lines that have not been accessed for a long time should be evicted
 */
int selectEvictionLine(cache_set_t cache_set)
{
    int i;
    int worst_line = 0;
    unsigned long worst_score = 0;

    for (i = 0; i < E; i++) {
        // Calculate an eviction score
        unsigned long score = 
            (cache_set[i].access_count == 0 ? ULONG_MAX : 
             (ULONG_MAX / cache_set[i].access_count)) +  
            (cache_set[i].priority * 1000UL) +           
            ((time(NULL) - cache_set[i].last_access) * 10UL); 

        // If line is invalid, it has the absolute highest score
        if (!cache_set[i].valid) return i;

        // Track line with worst (highest) score
        if (score > worst_score) {
            worst_score = score;
            worst_line = i;
        }
    }

    return worst_line;
}


 // Access data at memory address addr.

void accessData(mem_addr_t addr)
{
    int i;
    time_t current_time = time(NULL);

    mem_addr_t set_index = (addr >> b) & set_index_mask;
    mem_addr_t tag = addr >> (s+b);

    cache_set_t cache_set = cache[set_index];

    // Check for hit and update hit line
    for(i = 0; i < E; i++) {
        if(cache_set[i].valid && cache_set[i].tag == tag) {
            hit_count++;
            if(verbosity)
                printf("hit ");
            
            // Enhance hit line properties
            cache_set[i].access_count++;
            cache_set[i].last_access = current_time;
            cache_set[i].priority = (cache_set[i].priority < 255) ? 
                                     cache_set[i].priority + 1 : 255;
            cache_set[i].dirty = 1;  // Mark as potentially modified
            
            return;
        }
    }

    // In case there's miss handeling
    miss_count++;
    if (verbosity)
        printf("miss ");

    // Finds line to evict
    int target_line = selectEvictionLine(cache_set);

    // Check if we're evicting an existing line
    if (cache_set[target_line].valid) {
        eviction_count++;
        if (verbosity)
            printf("eviction ");
    }

    // Insert new entry
    cache_set[target_line].valid = 1;
    cache_set[target_line].tag = tag;
    cache_set[target_line].last_access = current_time;
    cache_set[target_line].access_count = 1;
    // Initial priority for new entry
    cache_set[target_line].priority = 10;  
    // New entry, not modified yet
    cache_set[target_line].dirty = 0;  
}


// Replay the trace file and simulate the cache for each memory access
void replayTrace(char* trace_fn)
{
    char buf[1000];
    mem_addr_t addr=0;
    unsigned int len=0;
    FILE* trace_fp = fopen(trace_fn, "r");

    if(!trace_fp){
        fprintf(stderr, "%s: %s\n", trace_fn, strerror(errno));
        exit(1);
    }

    while( fgets(buf, 1000, trace_fp) != NULL) {
        if(buf[1]=='S' || buf[1]=='L' || buf[1]=='M') {
            sscanf(buf+3, "%llx,%u", &addr, &len);
      
            if(verbosity)
                printf("%c %llx,%u ", buf[1], addr, len);

            accessData(addr);

            // If the instruction is R/W then access again
            if(buf[1]=='M')
                accessData(addr);
            
            if (verbosity)
                printf("\n");
        }
    }

    fclose(trace_fp);
}
void printUsage(char* argv[])
{
    printf("Usage: %s [-hv] -s <num> -E <num> -b <num> -t <file>\n", argv[0]);
    printf("Options:\n");
    printf("  -h         Print this help message.\n");
    printf("  -v         Optional verbose flag.\n");
    printf("  -s <num>   Number of set index bits.\n");
    printf("  -E <num>   Number of lines per set.\n");
    printf("  -b <num>   Number of block offset bits.\n");
    printf("  -t <file>  Trace file.\n");
    printf("\nExamples:\n");
    printf("  linux>  %s -s 4 -E 1 -b 4 -t traces/yi.trace\n", argv[0]);
    exit(0);
}
int main(int argc, char* argv[])
{
    char c;

    while( (c=getopt(argc,argv,"s:E:b:t:vh")) != -1){
        switch(c){
        case 's':
            s = atoi(optarg);
            break;
        case 'E':
            E = atoi(optarg);
            break;
        case 'b':
            b = atoi(optarg);
            break;
        case 't':
            trace_file = optarg;
            break;
        case 'v':
            verbosity = 1;
            break;
        case 'h':
            printUsage(argv);
            exit(0);
        default:
            printUsage(argv);
            exit(1);
        }
    }

    // checks for args 
    if (s == 0 || E == 0 || b == 0 || trace_file == NULL) {
        printf("%s: Missing required command line argument\n", argv[0]);
        printUsage(argv);
        exit(1);
    }

    // Calculate S, E and B from command line args
    S = (unsigned int) pow(2, s);
    B = (unsigned int) pow(2, b);
 
    // Initialize the cache
    initCache();

    replayTrace(trace_file);

    // Output the hit and miss statistics for the autograder
    FILE* results_file = fopen(".csim_results", "w");
    if (results_file) {
        fprintf(results_file, "%d %d %d", hit_count, miss_count, eviction_count);
        fclose(results_file);
    }

    // Free allocated memory 
    freeCache();

    return 0;
}