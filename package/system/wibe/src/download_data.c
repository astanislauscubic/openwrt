#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CONNECT_TIMEOUT_SECS 2
#define HTTP_PORT 80

static int create_non_blocking_socket(void)
{
	int sock = socket(PF_INET, SOCK_STREAM,	IPPROTO_TCP);
  if (sock == -1)
    return sock;

  int sock_flags = fcntl(sock, F_GETFL);
  if (sock_flags < 0)
    return sock_flags;
  int err = fcntl(sock, F_SETFL, sock_flags | O_NONBLOCK);
  if (err < 0)
    return err;

  return sock;
}

static int connect_to_host(int sock, const char *host)
{
  struct addrinfo *addr_info = NULL;
  struct addrinfo hint;
  memset(&hint, 0, sizeof(hint));
  hint.ai_family = AF_INET;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_flags    = 0;
  int err = getaddrinfo(host, NULL, &hint, &addr_info);
  if (err < 0)
  {
    fprintf(stderr, "%s\n", gai_strerror(err));
    errno = -err;
    return -1;
  }

  struct sockaddr_in *addr = (struct sockaddr_in *)(addr_info->ai_addr);
  addr->sin_port = htons(HTTP_PORT);
  err = connect(sock, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
  if (err < 0 && errno != EINPROGRESS)
  {
    perror("connect");
    return err;
  }

  freeaddrinfo(addr_info);

  return 0;
}

static int wait_for_connect_to_complete(int sock, int timeout_seconds)
{
  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(sock, &fdset);
  struct timeval tv = { .tv_sec = timeout_seconds, .tv_usec = 0 };
  int writeable = select(sock + 1, NULL, &fdset, NULL, &tv);
  if (writeable < 1)
    return -1;

  return 0;
}

static int make_socket_blocking(int sock)
{
  int sock_flags = fcntl(sock, F_GETFL);
  if (sock_flags < 0)
    return sock_flags;
  int err = fcntl(sock, F_SETFL, sock_flags & ~O_NONBLOCK);
  if (err < 0)
    return err;

  return 0;
}

static int fork_to_background(void)
{
  pid_t pid = fork();
  if (pid < 0)
    return -1;
  else if (pid > 0)
    _exit(0);

  umask(0);
  pid_t sid = setsid();
  if (sid < 0)
    return -1;
  if ((chdir("/")) < 0)
    return -1;
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  return 0;
}

static int request_file(int sock, const char *host, const char *file)
{
  char *command;
  asprintf(&command,
           "GET %s HTTP/1.1\r\n"
           "HOST: %s\r\n"
           "Connection: close\r\n"
           "\r\n", file, host);
  size_t command_length = strlen(command);
	int err = write(sock, command, command_length);
  free(command);
  if (err != command_length)
    return err;

  return 0;
}

static void eat_all_data(int sock)
{
  int bytes;
  do
  {
    char buffer[10 * 1024];
    bytes = read(sock, buffer, sizeof(buffer) - 1);
  }
  while (bytes > 0);
}

static void close_socket(int sock)
{
	close(sock);
}

static int download_data(const char *host, const char* file)
{
  int sock = create_non_blocking_socket();
  if (sock < 0)
    return sock;

  int err = connect_to_host(sock, host);
  if (err < 0)
    return -1;

  err = wait_for_connect_to_complete(sock, CONNECT_TIMEOUT_SECS);
  if (err < 0)
    return -2;

  err = make_socket_blocking(sock);
  if (err < 0)
    return -3;

  err = fork_to_background();
  if (err < 0)
    return -4;

  err = request_file(sock, host, file);
  if (err < 0)
    return -5;

  eat_all_data(sock);

  close_socket(sock);

	return 0;
}

int main(int argc, char *argv[])
{
  char msg[64];
  if (argc != 3)
  {
    fprintf(stderr, "Usage: %s <host> <file>\n", argv[0]);
    return -1;
  }

  int err = download_data(argv[1], argv[2]);
  if (err != 0)
  {
    sprintf(msg, "Failed to download data %d", err);
    perror(msg);
  }

  return err;
}
