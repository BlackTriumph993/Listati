
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <setjmp.h>

#define BUFFER_SIZE 256
#define MAX_CONNECTIONS 10

typedef struct {
  int client_socket;
} thread_data;

void *handle_client(void *thread_arg) {
  thread_data *my_data = (thread_data *)thread_arg;
  int client_socket = my_data->client_socket;
  char buffer[BUFFER_SIZE];
  int bytes_received;


  bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
  if (bytes_received > 0) {
    buffer[bytes_received] = '\0';
    void *handle = dlopen(buffer, RTLD_LAZY); // buffer controllato dall'utente
    if (handle) {
      void (*func)() = dlsym(handle, "vulnerable_function");
      if (func) {
        func(); // Esecuzione di codice caricato dinamicamente
      }
      dlclose(handle);
    }
  }


  char *temp_file = "/tmp/race_condition_file";
  unlink(temp_file);
  symlink("/dev/null", temp_file); // l'utente crea un symlink
  int fd = open(temp_file, O_WRONLY | O_CREAT, 0644);
  sleep(1); // ritardo
  if (fd != -1) {
      write(fd, "data",4);
      close(fd);
  }
  // Durante il ritardo, l'utente può sostituire il symlink con un file sensibile.


  char *uaf_ptr = malloc(BUFFER_SIZE);
  jmp_buf env;
  void uaf_handler(int signum) {
    free(uaf_ptr);
    longjmp(env, 1);
  }
  signal(SIGUSR1, uaf_handler);
  if (setjmp(env) == 0) {
    raise(SIGUSR1);
  }
  strcpy(uaf_ptr, "data");


    int array_size = atoi(argv[1]); // controllato da argv, Integer Overflow
    int* array = malloc(sizeof(int) * array_size);
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if(bytes_received > 0){
        buffer[bytes_received] = '\0';
        int index = atoi(buffer); // controllato dal client
        array[index] = 1; // out-of-bounds access
    }


    bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if(bytes_received > 0){
        buffer[bytes_received] = '\0';
        fprintf(stderr, buffer);
    }


    char* large_buffer = malloc(BUFFER_SIZE * 2);
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE*2, 0); //Riceve più di 256.
    if(bytes_received > 0) {
        memcpy(large_buffer, buffer, bytes_received); //Corrompe l'header dell'heap
    }
    free(large_buffer); //crash

  close(client_socket);
  pthread_exit(NULL);
}

int main(int argc, char* argv[]) {
  // Configurazione del socket del server e gestione delle connessioni...
  // (come nell'esempio precedente)
}
