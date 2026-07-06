#ifndef OXIDE_LINUX_SEQLOCK_H
#define OXIDE_LINUX_SEQLOCK_H

typedef struct { unsigned int seq; unsigned int lock; } seqlock_t;

void seqlock_init(seqlock_t *lock);
void write_seqlock(seqlock_t *lock);
void write_sequnlock(seqlock_t *lock);
unsigned int read_seqbegin(seqlock_t *lock);
int read_seqretry(seqlock_t *lock, unsigned int start);

#endif
