
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 256

int main(int argc, char *argv[]) {

  char buffer[BUFFER_SIZE];
  strcpy(buffer, argv[1]); // Uso di strcpy non sicuro


  char format_buffer[BUFFER_SIZE];
  sprintf(format_buffer, argv[2]); // Uso di sprintf non sicuro
  printf(format_buffer);


  int size = atoi(argv[3]);
  int *array = malloc(size * sizeof(int)); // Potenziale overflow
  // ... utilizzo di array ...
  free(array);


  char *ptr = malloc(BUFFER_SIZE);
  free(ptr);
  strcpy(ptr, "data"); // Uso di ptr dopo il free


  char *heap_buffer = malloc(BUFFER_SIZE);
  char *input = argv[4];
  while (*input) {
    if (strlen(heap_buffer) >= BUFFER_SIZE - 1) {
      // Intentionally not handling the overflow to demonstrate the vuln
      heap_buffer[strlen(heap_buffer)] = *input; // Potenziale heap overflow
    }
    input++;
  }
  heap_buffer[strlen(heap_buffer)] = '\0';
  printf("%s\n", heap_buffer);
  free(heap_buffer);

  // 6. Double Free (CVSS 3.1: 7.5 - Alto)
  char *df_ptr = malloc(BUFFER_SIZE);
  free(df_ptr);
  free(df_ptr); // Double free


  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  // Simulo la mancata chiusura, anche se normalmente sarebbe alla fine.
  // ... codice con sockfd ...
  //close(sockfd); // Mancata chiusura descrittore

  return 0;
}
