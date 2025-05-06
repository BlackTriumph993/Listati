
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

#define BUFFER_SIZE 256
#define MAX_CONNECTIONS 10

// Struct per passare dati ai thread
typedef struct {
  int client_socket;
} thread_data;

// Funzione del thread
void *handle_client(void *thread_arg) {
  thread_data *my_data = (thread_data *)thread_arg;
  int client_socket = my_data->client_socket;
  char buffer[BUFFER_SIZE];
  int bytes_received;


  char filename[BUFFER_SIZE];
  char command[BUFFER_SIZE];
  bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
  if (bytes_received > 0) {
    buffer[bytes_received] = '\0';
    sprintf(filename, "/tmp/%s.txt", buffer); // Uso non sicuro di sprintf
    sprintf(command, "touch %s", filename); // Uso non sicuro di sprintf
    system(command);
  }


  char *temp_file = "/tmp/race_condition_file";
  int fd = open(temp_file, O_CREAT | O_WRONLY, 0644);
  sleep(1); // Simula un ritardo
  if (fd != -1) {
    write(fd, "Data", 4);
    close(fd);
  }
  // Un altro processo potrebbe modificare/eliminare il file durante il ritardo.


  char *signal_ptr = malloc(BUFFER_SIZE);
  void signal_handler(int signum) {
    free(signal_ptr);
    // ... altro codice ...
  }
  signal(SIGUSR1, signal_handler);
  // ... (nel main) send signal SIGUSR1 ...
  strcpy(signal_ptr, "data"); // Use-After-Free


  char *df_ptr = malloc(BUFFER_SIZE);
  char *copy_ptr = df_ptr;
  free(df_ptr);
  free(copy_ptr); // Double Free


  char log_message[BUFFER_SIZE];
  bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
  if (bytes_received > 0) {
    buffer[bytes_received] = '\0';
    sprintf(log_message, buffer); // Uso non sicuro di sprintf
    printf("[LOG] ");
    printf(log_message);
    printf("\n");
  }


  // Questo esempio simula la logica. In un sistema reale, dovresti
  // avere una libreria SQL e connessione al DB.
  char query[BUFFER_SIZE * 2];
  bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
  if (bytes_received > 0) {
    buffer[bytes_received] = '\0';
    sprintf(query, "SELECT * FROM users WHERE username = '%s'", buffer);
    printf("Query: %s\n", query); // Stampa la query (per dimostrazione)
    // In un sistema reale, si eseguirebbe la query.
    // La mancata sanificazione di 'buffer' rende la query vulnerabile.
  }

  close(client_socket);
  pthread_exit(NULL);
}

int main() {
  int server_socket, client_socket;
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_len = sizeof(client_addr);
  pthread_t threads[MAX_CONNECTIONS];
  int thread_count = 0;

  // Configurazione del socket del server
  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(8080);
  bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
  listen(server_socket, MAX_CONNECTIONS);

  // Gestione delle connessioni in entrata
  while (thread_count < MAX_CONNECTIONS) {
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) {
      perror("accept failed");
      continue;
    }

    thread_data *my_data = malloc(sizeof(thread_data));
    my_data->client_socket = client_socket;

    if (pthread_create(&threads[thread_count], NULL, handle_client, (void *)my_data) != 0) {
      perror("Thread creation failed");
      close(client_socket); // Assicurarsi di chiudere il socket anche in caso di errore
      free(my_data);
      continue;
    }
    thread_count++;
    pthread_detach(threads[thread_count - 1]); // Detach the threads
  }

  close(server_socket);
  return 0;
}
