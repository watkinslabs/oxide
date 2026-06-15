#include <stdio.h>
#include <pthread.h>
static int counter = 0;
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static void* worker(void* arg){
    long n = (long)arg;
    for(int i=0;i<1000;i++){ pthread_mutex_lock(&m); counter++; pthread_mutex_unlock(&m); }
    return (void*)(n*2);
}
int main(void){
    pthread_t t[4]; 
    for(long i=0;i<4;i++) pthread_create(&t[i], NULL, worker, (void*)i);
    long sum=0; for(int i=0;i<4;i++){ void* r; pthread_join(t[i], &r); sum += (long)r; }
    printf("counter=%d joinsum=%ld\n", counter, sum);
    return 0;
}
