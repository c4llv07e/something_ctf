#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#define VERY_SECURE_XOR_KEY 0x04110073

typedef struct Account {
 char *name;
 char *master_password;
} Account;

typedef struct CryptedPassword {
 Account *account;
 size_t value_size;
 char *value;
} Token;

size_t accounts_length;
Account **accounts;

size_t tokens_length;
Token **tokens;

int
socket_send_message(int socket, char *message) {
 size_t message_length;
 message_length = strlen(message);
 return (send(socket, message, message_length, 0)) == message_length;
}

int
socket_prompt(int socket, char *message, size_t output_size, char *output) {
 socket_send_message(socket, message);
 return recv(socket, output, output_size, 0) != 0;
}

Account *
account_find_by_name(char *name) {
 for (int i = 0; i < accounts_length; ++i) {
  Account *iter_account = accounts[i];
  if (strcmp(iter_account->name, name) == 0) {
   return iter_account;
  }
 }
 return NULL;
}

Account *
account_login(int client_socket) {
 Account *account;
 char username[0x40];
 char master_password[0x40];
 socket_prompt(client_socket, "Enter your username: ", (sizeof username), username);
 socket_prompt(client_socket, "Enter your master password: ", (sizeof master_password), master_password);

 if ((account = account_find_by_name(username)) == NULL) {
  socket_send_message(client_socket, "Can't find required account!\n");
  return NULL;
 }

 if (strcmp(account->master_password, master_password) != 0) {
  socket_send_message(client_socket, "Wrong master password!\n");
  return NULL;
 }

 return account;
}

void
xor_string_string(size_t value_size, char *value, size_t key_size, char *key, char *result) {
 for (size_t i = 0; i < value_size; ++i) {
  result[i] = value[i] ^ key[i % key_size];
 }
}

int
token_decrypt(Token *token, size_t result_size, char *result) {
 Account *account = token->account;
 char *master_password = account->master_password;
 size_t master_password_length = strlen(master_password);
 xor_string_string(
  token->value_size,
  token->value,
  master_password_length,
  master_password,
  result);
 return 0;
}

int
token_encrypt(Account *account, char *value, size_t result_size, char *result) {
 size_t value_size = strlen(value);
 char *master_password = account->master_password;
 size_t master_password_length = strlen(master_password);
 xor_string_string(
  value_size,
  value,
  master_password_length,
  master_password,
  result);
 return 0;
}

/* Handles client communication.
   NOTE: Client socket will be closed at the end. */
int
handle_client(int client_socket) {
 int error_value;
 char read_buffer[0x200];
 int action_number;

 error_value = 0;

 socket_send_message(client_socket,
                     "Welcome to the Xorage! Here you can store your information with encryption.\n"
                     "What do you want to do?\n"
                     "1. Create new account.\n"
                     "2. Store info.\n"
                     "3. List your account's secrets.\n"
                     "4. List all accounts\n"
                     "> ");
 recv(client_socket, read_buffer, (sizeof read_buffer), 0);

 if ((action_number = atoi(read_buffer)) == 0) {
  socket_send_message(client_socket, "Not a number!\n");
  error_value = -1;
  goto defer;
 }

 switch (action_number) {
 case 1: {
  Account *account;
  char username[0x40];
  char master_password[0x40];
  socket_prompt(client_socket, "Enter your username: ", (sizeof username), username);
  socket_prompt(client_socket, "Enter your master password: ", (sizeof master_password), master_password);
  account = malloc((sizeof *account));
  accounts = realloc(accounts, accounts_length + 1);
  accounts[accounts_length] = account;
  accounts_length += 1;
 } break;

 case 2: {
  Account *account;
  char secret[0x100];
  if ((account = account_login(client_socket)) == NULL) {
   error_value = -1;
   goto defer;
  }
  socket_prompt(client_socket, "Enter your secret: ", (sizeof secret), secret);
 } break;

 case 3: {
  Account *account;
  if ((account = account_login(client_socket)) == NULL) {
   error_value = -1;
   goto defer;
  }

  for (int i = 0; i < tokens_length; ++i) {
   Token *token = tokens[i];
   if (token->account == account) {
    char token_text[0x40];
    token_decrypt(token, (sizeof token_text), token_text);
    socket_send_message(client_socket, "> ");
    socket_send_message(client_socket, token_text);
    socket_send_message(client_socket, "\n");
   }
  }
 } break;

 case 4: {
  for (int i = 0; i < accounts_length; ++i) {
   Account *account;
   account = accounts[i];
   socket_send_message(client_socket, "> ");
   socket_send_message(client_socket, account->name);
   socket_send_message(client_socket, "\n");
  }
 } break;

 default: {
  socket_send_message(client_socket, "Unknown action!\n");
  error_value = -1;
  goto defer;
 } break;
 }

defer:
 if (client_socket != 0) {
  close(client_socket);
 }
 return error_value;
}

int
main(void) {
 int client_sockaddr_size;
 int client_socket;
 int server_socket;
 int enable_bit;
 struct sockaddr_in server_sockaddr, client_sockaddr;

 accounts = malloc((sizeof *accounts));
 accounts_length = 0;

 tokens = malloc((sizeof *tokens));
 tokens_length = 0;

 server_socket = socket(AF_INET, SOCK_STREAM, 0);
 if (server_socket == -1) {
  fprintf(stderr, "error, can't create socket\n");
  return -1;
 }

 enable_bit = 1;
 if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &enable_bit, (sizeof enable_bit)) < 0) {
  fprintf(stderr, "error, can't set socket option\n");
  return -1;
 }

 memset(&server_sockaddr, 0x0, (sizeof server_sockaddr));
 server_sockaddr.sin_family = AF_INET;
 server_sockaddr.sin_addr.s_addr = INADDR_ANY;
 server_sockaddr.sin_port = htons(8000);

 if (bind(server_socket, (struct sockaddr *)&server_sockaddr, (sizeof server_sockaddr)) < 0) {
  fprintf(stderr, "error, can't bind socket to the address %d\n", errno);
  return -1;
 }

 listen(server_socket, 3);

 while (1) {
  client_sockaddr_size = (sizeof client_sockaddr);
  client_socket = accept(server_socket, (struct sockaddr *)&client_sockaddr, (socklen_t *)&client_sockaddr_size);
  if (client_socket == -1) {
   fprintf(stderr, "error, can't accept socket %d\n",
           errno);
   continue;
  }

  handle_client(client_socket);
 }
 close(server_socket);

 return 0;
}
