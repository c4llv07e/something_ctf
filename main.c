#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

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
pipe_closed(int pipe) {
 struct pollfd pfd = {
  .fd = pipe,
  .events = POLLOUT,
 };
 if (poll(&pfd, 1, 1) < 0) {
  return 0;
 }

 return pfd.revents & POLLERR;
}

int
socket_send_message(int socket, char *message) {
 size_t message_length;
 if (pipe_closed(socket)) {
  return -1;
 }
 message_length = strlen(message);
 return (send(socket, message, message_length, MSG_NOSIGNAL)) == -1;
}

int
socket_prompt(int socket, char *message, size_t result_size, char *result) {
 size_t recv_size;
 if (pipe_closed(socket)) {
  return -1;
 }
 if (socket_send_message(socket, message) != 0) {
  return -1;
 }
 recv_size = recv(socket, result, result_size, 0);
 result[recv_size] = 0;
 result[strcspn(result, "\n")] = 0;
 return recv_size <= 0;
}

Account *
account_find_by_name(char *name) {
 for (size_t i = 0; i < accounts_length; ++i) {
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
 if (socket_prompt(client_socket, "Enter your username: ", (sizeof username), username) != 0) {
  return NULL;
 }
 if (socket_prompt(
      client_socket,
      "Enter your master password: ",
      (sizeof master_password),
      master_password) != 0) {
  return NULL;
 }

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

Account *
account_new(char *name, char *master_password) {
 Account *account;
 account = malloc((sizeof *account));
 account->name = malloc((sizeof *account->name) * strlen(name));
 strcpy(account->name, name);
 account->master_password = malloc((sizeof *account->master_password) * strlen(master_password));
 strcpy(account->master_password, master_password);
 accounts = realloc(accounts, (sizeof *accounts) * (accounts_length + 1));
 accounts[accounts_length] = account;
 accounts_length += 1;
 return account;
}

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
size_t
b64_encoded_size(size_t inlen) {
 size_t ret;

 ret = inlen;
 if (inlen % 3 != 0) {
  ret += 3 - (inlen % 3);
 }
 ret /= 3;
 ret *= 4;

 return ret;
}

void
b64_encode(size_t text_size, char *text, char *result) {
 size_t elen;
 size_t i;
 size_t j;
 size_t v;

 elen = b64_encoded_size(text_size);
 result[elen] = '\0';

 for (i=0, j=0; i<text_size; i+=3, j+=4) {
  v = text[i];
  v = i+1 < text_size ? v << 8 | text[i+1] : v << 8;
  v = i+2 < text_size ? v << 8 | text[i+2] : v << 8;

  result[j]   = b64chars[(v >> 18) & 0x3F];
  result[j+1] = b64chars[(v >> 12) & 0x3F];
  if (i+1 < text_size) {
   result[j+2] = b64chars[(v >> 6) & 0x3F];
  } else {
   result[j+2] = '=';
  }
  if (i+2 < text_size) {
   result[j+3] = b64chars[v & 0x3F];
  } else {
   result[j+3] = '=';
  }
 }
}

void
xor_string_string(size_t value_size, char *value, size_t key_size, char *key, char *result) {
 for (size_t i = 0; i < value_size; ++i) {
  result[i] = value[i] ^ key[i % key_size];
 }
}

int
token_decrypt(Token *token, char *result) {
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
token_encrypt(Account *account, char *value, char *result) {
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

Token *
token_new(Account *account, char *secret) {
 Token *token;
 token = malloc((sizeof *token));
 token->value_size = strlen(secret);
 token->value = malloc(token->value_size);
 token_encrypt(account, secret, token->value);
 token->account = account;
 tokens = realloc(tokens, (sizeof *tokens) * (tokens_length + 1));
 tokens[tokens_length] = token;
 tokens_length += 1;
 return token;
}

/* Handles client communication.
   NOTE: Client socket will be closed at the end. */
int
handle_client(int client_socket) {
 int error_value;
 char read_buffer[0x200];
 int action_number;

 error_value = 0;

 while (error_value == 0) {

  if (socket_prompt(
   client_socket,
   "Welcome to the Xorage! Here you can store your information with encryption.\n"
   "What do you want to do?\n"
   "1. Create new account.\n"
   "2. Store secret.\n"
   "3. List your account's secrets.\n"
   "4. List all accounts.\n"
   "5. List all encrypted secrets.\n"
   "> ",
   (sizeof read_buffer), read_buffer) != 0) {
   error_value = -1;
   goto defer;
  }

  if ((action_number = atoi(read_buffer)) == 0) {
   socket_send_message(client_socket, "Not a number!\n");
   error_value = -1;
   goto defer;
  }

  switch (action_number) {
  case 1: {
   char username[0x40];
   char master_password[0x40];
   if (socket_prompt(client_socket, "Enter your username: ", (sizeof username), username) != 0) {
    error_value = -1;
    goto defer;
   }
   if (socket_prompt(
        client_socket,
        "Enter your master password: ",
        (sizeof master_password),
        master_password) != 0) {
    error_value = -1;
    goto defer;
   }
   account_new(username, master_password);
  } break;

  case 2: {
   Account *account;
   char secret[0x100];
   if ((account = account_login(client_socket)) == NULL) {
    error_value = -1;
    goto defer;
   }
   socket_prompt(client_socket, "Enter your secret: ", (sizeof secret), secret);
   token_new(account, secret);
  } break;

  case 3: {
   Account *account;
   if ((account = account_login(client_socket)) == NULL) {
    error_value = -1;
    goto defer;
   }

   socket_send_message(client_socket, "Account's secrets:\n");
   for (size_t i = 0; i < tokens_length; ++i) {
    Token *token = tokens[i];
    if (token->account == account) {
     char token_text[0x40];
     token_decrypt(token, token_text);
     socket_send_message(client_socket, "< ");
     socket_send_message(client_socket, token_text);
     socket_send_message(client_socket, "\n");
    }
   }
  } break;

  case 4: {
   for (size_t i = 0; i < accounts_length; ++i) {
    Account *account;
    account = accounts[i];
    if (account->name == NULL) {
     fprintf(stderr, "warning, account with NULL name.\n");
    }
    socket_send_message(client_socket, "< ");
    socket_send_message(client_socket, account->name);
    socket_send_message(client_socket, "\n");
   }
  } break;

  case 5: {
   for (size_t i = 0; i < tokens_length; ++i) {
    Token *token = tokens[i];
    char *token_text;
    token_text = malloc(token->value_size * (sizeof token->value));
    b64_encode(token->value_size, token->value, token_text);
    socket_send_message(client_socket, "< \"");
    socket_send_message(client_socket, token->account->name);
    socket_send_message(client_socket, "\": \"");
    socket_send_message(client_socket, token_text);
    socket_send_message(client_socket, "\"\n");
    free(token_text);
   }
  } break;

  default: {
   socket_send_message(client_socket, "Unknown action!\n");
   error_value = -1;
   goto defer;
  } break;
  }
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

/* #ifdef DEBUG */
/*  { */
/*   Account *test_account; */
/*   test_account = account_new("user", "123"); */
/*   token_new(test_account, "int main() { *(char*)0 = 0; return 0; }"); */
/*  } */
/* #endif */

/*  Account *alice_account; */
/*  alice_account = account_new("alice", "shpctf{4lIc3_1n_tH3_x0r_w0r1d}"); */
/*  token_new(alice_account, "'Twas brillig, and the slithy toves"); */
/*  token_new(alice_account, "Did gyre and gimble in the wabe;"); */
/*  token_new(alice_account, "All mimsy were the borogoves,"); */
/*  token_new(alice_account, "And the mome raths outgrabe."); */

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
