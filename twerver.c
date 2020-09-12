#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
    #define PORT 54646
#endif

#define LISTEN_SIZE 5
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username: "
#define JOIN_MSG " has just joined.\r\n"
#define INVALID_COMMAND "Invalid command.\r\n"
#define USERNAME_NOT_EXIST "username does not exist.\r\n"
#define DUPLICATE_USERNAME "This username already exists. Try again.\r\n"
#define EMPTY_USERNAME "Please enter a non-empty username. Try again.\r\n"

//send
#define SEND_MSG "send"
#define MSG_LIMIT_REACHED "Unsuccessful: you have reached the maximum number of messages you can send.\r\n"

// show
#define SHOW_MSG "show"
#define CLIENT_WROTE " wrote: "

//follow
#define FOLLOW_MSG "follow"
#define FOLLOW_EXISTS "Unsuccessful: You have already followed this client.\r\n"
#define FOLLOWING_LIMIT_REACHED "Unsuccessful: you have already reached following limit.\r\n"
#define FOLLOWER_LIMIT_REACHED "The client you are trying to follow already reached follower limit.\r\n"
#define FOLLOW_SELF "You cannot follow yourself.\r\n"

// unfollow
#define UNFOLLOW_MSG "unfollow"
#define UNFOLLOW_SELF "You cannot unfollow yourself.\r\n"
#define UNFOLLOW_ERR "You did not follow this user.\r\n"

// quit
#define QUIT_MSG "quit"
#define BYE "Goodbye "

/** 
 * Write nbyte bytes from buf to fd, with error checking. Return number of bytes 
 * successfully written.
 * If unsuccessful, perror with message error_message.
 **/
int Write(int fd, const void *buf, size_t nbyte, char *error_message) {
    int res;
    if ((res = write(fd, buf, nbyte)) != nbyte) {
        perror(error_message);
        exit(1);
    }
    return res;
}

/** 
 * Close fildes, with error checking. Return type void because case -1 is handled.
 * If unsuccessful, perror with message error_message.
 **/
void Close(int fildes, char *error_message) {
    if (close(fildes) == -1) {                
        perror(error_message);                
        exit(1); 
    }           
}

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
};

// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++) {
        p->message[i][0] = '\0';
    }

    for(int i = 0; i < FOLLOW_LIMIT; i++) {
        (p->followers)[i] = NULL;
        (p->following)[i] = NULL;
    }

    *clients = p;
}


/**
 * Remove client with file discriptor fd from clients.
 **/
void remove_client_from_list(struct client **clients, int fd) {
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        if (clients[i] && fd == (clients[i])->fd) {
            clients[i] = NULL;
            return;
        }
    }
}


/**
 * Remove p from all other clients' follow/unfollow list. 
 **/
void remove_follow(struct client *p) {

    for (int i = 0; i < FOLLOW_LIMIT; i++) {

        if ((p->followers)[i]) {
            remove_client_from_list((p->followers)[i]->following, p->fd);

            // Print server log
            printf("%s no longer follows %s because the former disconnects\n", p->username, (p->followers)[i]->username);

        }
        

        if ((p->following)[i]) {
            remove_client_from_list((p->following)[i]->followers, p->fd);

            // Print server log
            printf("%s no longer has %s as a follower because the latter disconnects\n", (p->following)[i]->username, p->username);
        }
    }
}


// Send the message s to all clients in active_clients. 
void announce(struct client *active_clients, char *s) {
    for (struct client *p = active_clients; p != NULL; p = p->next) {
        int fd = p->fd;
        if (fd != -1) {
            Write(fd, s, strlen(s), "write message to all clients");
        }
    }
}


/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {

        //the username of the removed client
        char removed_username[strlen((*p)->username) + 1];
        removed_username[0] = '\0';
        strncat(removed_username, (*p)->username, strlen((*p)->username) + 1);

        remove_follow(*p);

        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        Close((*p)->fd, "Close socket");
        free(*p);
        *p = t;

        // Notify all users p is gone.
        int bye_message_length = strlen(BYE) + strlen(removed_username) + 2;
        char bye_message[bye_message_length + 1];
        bye_message[0] = '\0';
        strncat(bye_message, BYE, bye_message_length + 1);
        strncat(bye_message, removed_username, bye_message_length + 1 - strlen(bye_message));
        strncat(bye_message, "\r\n", bye_message_length + 1 - strlen(bye_message));
        announce(*clients, bye_message);

    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
        exit(1);
    }
}


// Move client c from new_clients list to active_clients list. 
void activate_client(struct client *c, struct client **active_clients_ptr, struct client **new_clients_ptr) {

    // Create notification to be sent to active clients when a new user becomes active
    char notification[BUF_SIZE];
    notification[0] = '\0';
    strncat(notification, c->username, BUF_SIZE);
    strncat(notification, JOIN_MSG, BUF_SIZE - strlen(notification));

    if (c == *new_clients_ptr) {
        *new_clients_ptr = c->next;
        c->next = *active_clients_ptr;
        *active_clients_ptr = c;
        announce(*active_clients_ptr, notification);
        printf("%s has just joined.\n", c->username);
        return;
    }
    for (struct client **p = new_clients_ptr; *p != NULL; *p = (*p)->next) {
        if ((*p)->next == c) {
            (*p)->next = c->next;
            c->next = *active_clients_ptr;
            *active_clients_ptr = c;
            announce(*active_clients_ptr, notification);
            return;
        }
    }
    exit(1);
}


/**
 * Return pointer to the first character after the network newline in buf. Return -1 if no network newline is found.
 **/
int find_network_newline(const char *buf, int n) {
    for (int i = 0; i < n - 1; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n') {
            return i + 2;
        }
    }
    return -1;
}


/**
 * Return a pointer to client in clients, who has username as his username.
 **/
struct client *getClient(char *username, struct client *clients) {
    for (struct client *p = clients; p != NULL; p = p->next) {
        if (strcmp(p->username, username) == 0) {
            return p;
        }
    }
    return NULL;
}


/**
 * Return 1 if username is valid, 0 otherwise. Notify client at fd if anything goes wrong. A username is invalid if it is the username of a client in active_clients.
 **/
int isAcceptableUsername(char *username, int fd, struct client *active_clients) {
    
    // username is invalid if it is empty
    if (strlen(username) == 0) {
        Write(fd, EMPTY_USERNAME, strlen(EMPTY_USERNAME), "write empty username message to client");
        return 0;
    }

    // username is invalid if it is a username of a client in active_clients.
    if (getClient(username, active_clients)) {
        Write(fd, DUPLICATE_USERNAME, strlen(DUPLICATE_USERNAME), "write duplicate username message to client");
        return 0;
    }

    return 1;
}


/**
 * Follow the client with the username, which is in the inbuf field of p. The username starts after the space char at space_index. The client we want to follow is in active_clients.
 **/
void client_follow(int space_index, struct client *p, struct client *active_clients) {
    
    // Get the username of the client to be followed. Return directly if it is the username of p because a client cannot follow himself
    char *username = p->inbuf + space_index + 1;
    if (strcmp(username, p->username) == 0) {
        Write(p->fd, FOLLOW_SELF, strlen(FOLLOW_SELF), "write follow self message to client");
        return;
    }

    // Get the client associated with username.
    struct client *target_p = getClient(username, active_clients);
    if (!target_p) {
        Write(p->fd, USERNAME_NOT_EXIST, strlen(USERNAME_NOT_EXIST), "write username not exist message to client");
        return;
    }

    // the index of the follower field of target_p, where we can inselt p into. It is -1 if we cannot insert anywhere.
    int follower_index = -1;
    // the index of the follower field of p, where we can inself target_p into. It is -1 if we cannot insert anywhere.
    int following_index = -1;

    // Check whether we can follow target_p
    for (int i = 0; i < FOLLOW_LIMIT && (follower_index == -1 || following_index == -1); i++) {

        // Handle if p wants to follow a client which he already follows
        if ((p->following)[i] && (p->following)[i] == target_p) {
            Write(p->fd, FOLLOW_EXISTS, strlen(FOLLOW_EXISTS), "write follow already exists message to client");
            return;
        }

        if (!(target_p->followers[i])) {
            follower_index = i;
        }
        if (!(p->followers[i])) {
            following_index = i;
        }
    }

    // Notify if we cannot insert p into target_p's follower field because it is full.
    if (follower_index == -1) {
        Write(p->fd, FOLLOWER_LIMIT_REACHED, strlen(FOLLOWER_LIMIT_REACHED), "write follower limit reached message to client");
    }

    // Notify if we cannot insert target_p into p's following field because it is full.
    if (following_index == -1) {
        Write(p->fd, FOLLOWING_LIMIT_REACHED, strlen(FOLLOWING_LIMIT_REACHED), "write following limit reached message to client");
    }

    // We are able to insert target_p into p's following field and p into target_p's follower field.
    if (follower_index != -1 && following_index != -1) {
        (p->following)[following_index] = target_p;
        printf("%s is following %s\n", p->username, username);

        (target_p->followers)[follower_index] = p;
        printf("%s is followed by %s\n", username, p->username);
    }
}


/**
 * Send the message contained in the inbuf field of p to all clients who are following p. The message starts after the space char at space_index.
 **/
void client_send(int space_index, struct client *p) {

    // Create the message full_message which we will send to clients.
    int full_message_length = strlen(p->inbuf + space_index + 1) + 4 + strlen(p->username);
    char full_message[full_message_length + 1];
    full_message[0] = '\0';
    strncat(full_message, p->username, full_message_length + 1);
    strncat(full_message, ": ", full_message_length + 1 - strlen(full_message));
    strncat(full_message, p->inbuf + space_index + 1, full_message_length + 1 - strlen(full_message));
    strncat(full_message, "\r\n", full_message_length + 1 - strlen(full_message));

    // Write the message to each of p's followers
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        if ((p->followers)[i]) {
            Write((p->followers)[i] -> fd, full_message, strlen(full_message), "write message to follower");
        }
    }

    // See at which index in the message field of p does not have a message. Then we copy the origional message there.
    for (int i = 0; i < MSG_LIMIT; i++) {
        if (strlen((p->message)[i]) == 0) {
            strncat((p->message)[i], p->inbuf + space_index + 1, BUF_SIZE);
            return;
        }
    }

    Write(p->fd, MSG_LIMIT_REACHED, strlen(MSG_LIMIT_REACHED), "write messege limit reached message to client");
}


/**
 * Write all messages p has sent to fd.
 **/
void write_all_msgs(struct client *p, int fd) {

    for (int i = 0; i < MSG_LIMIT; i++) {

        // The order we put messages into p->message is from index 0 to index MSG_LIMIT. Therefore, if we find p->message has nothing at index i, we know the indexes after it will not contain any message either.
        if (strlen((p->message)[i]) == 0) {
            return;
        }

        // Create the message we will send to fd.
        int full_message_length = strlen(p->username) + strlen(CLIENT_WROTE) + strlen((p->message)[i]) + 2;
        char full_message[full_message_length + 1];
        full_message[0] = '\0';
        strncat(full_message, p->username, full_message_length + 1);
        strncat(full_message, CLIENT_WROTE, full_message_length - strlen(full_message) + 1);
        strncat(full_message, (p->message)[i], full_message_length - strlen(full_message) + 1);
        strncat(full_message, "\r\n", full_message_length - strlen(full_message) + 1);

        Write(fd, full_message, strlen(full_message), "write show message to client");
    }
}


/**
 * Write all messages of all clients p is following to p's file discriptor.
 **/
void client_show(struct client *p) {
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        struct client *c = (p->following)[i];
        if (c) {
            write_all_msgs(c, p->fd);
        }
    }
}


/** 
 * Unfollow the client, whose username is in p->buf, from p. The username starts after the space char at space_index.
 **/
void client_unfollow(int space_index, struct client *p) {

    // Get the username and see if the client associated with it is p itself.
    char *username = p->inbuf + space_index + 1;
    if (strcmp(username, p->username) == 0) {
        Write(p->fd, UNFOLLOW_SELF, strlen(UNFOLLOW_SELF), "write unfollow self message to client");
        return;
    }

    // Find the client we want to unfollow from all clients that p is following. Remove it from our following list and remove p from the unfollowed client's followers list.
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        struct client *c = (p->following)[i];
        if (c && strcmp(c->username, username) == 0) {
            (p->following)[i] = NULL;
            printf("%s unfollows %s\n", p->username, c->username);
            remove_client_from_list(&(c->followers[i]), p->fd);
            printf("%s is no longer followed by %s\n", c->username, p->username);
            return;
        }
    }

    // Reach here only if did not successfully unfollow
    Write(p->fd, UNFOLLOW_ERR, strlen(UNFOLLOW_ERR), "write unfollow error message to client");
}


/**
 * Read input from the client fd to the inbuf field of p. Return -1 if client fd closes, 0 otherwise.
 **/
int update_inbuf(struct client *p) {
    int in_buf = 0;
    int nbytes;
    memset(p->inbuf, '\0', BUF_SIZE);
    p->in_ptr = p->inbuf;

    // Keep reading from client fd until (1) we see a network newline, or (2) client fd closes, or (3) read() is in error.
    while ((nbytes = read(p->fd, p->in_ptr, BUF_SIZE - in_buf - 1)) > 0) {
        
        // Print server log.
        printf("[%d] Read %d bytes\n", p->fd, nbytes);

        // Track how many characters are in inbuf
        in_buf += nbytes;
        int where;
        // If we find a network newline, null terminate inbuf and return.
        if ((where = find_network_newline(p->in_ptr, in_buf)) > 0) {
            p->in_ptr[where - 2] = '\0';

            // Print server log.
            printf("[%d] Found newline %s\n", p->fd, p->inbuf);

            return 0;
        }
        p->in_ptr += nbytes;
    }

    // Return -1 if client fd closes, 0 otherwise.
    if (nbytes < 0) {
        perror("read client input");
        exit(1);
    } else if (nbytes == 0) {
        printf("[%d] Read %d bytes\n", p->fd, nbytes);
        return -1;
    }
    return 0;
}


int main (int argc, char **argv) {
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal. 
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names). 
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or 
    // or receive announcements. 
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);
    free(server);

    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select 
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
            exit(1);
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
                fprintf(stderr, 
                    "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        int cur_fd, handled;
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    if (cur_fd == p->fd) {
                        handled = 1;

                        // Read from client fd to client.inbuf. If read returns 0, i.e. update_inbuf returns -1, we know the fd is closed. Then we remove the client.
                        if (update_inbuf(p) < 0) {
                            printf("Disconnected from %s\n", inet_ntoa(q.sin_addr));
                            remove_client(&new_clients, p->fd);
                            break;
                        }

                        strncat(p->username, p->inbuf, strlen(p->inbuf) + 1);

                        // Check the validity of the username. If valid, activate this client.
                        if (isAcceptableUsername(p->username, p->fd, active_clients)) {
                            activate_client(p, &active_clients, &new_clients);
                        } else {
                            p->username[0] = '\0';
                        }

                        break;
                    }
                }

                // If an active client enters something
                if (!handled) {

                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {

                            // Read from client fd to client.inbuf. If read returns 0, i.e. update_inbuf returns -1, we know the fd is closed. Then we remove the client.
                            if (update_inbuf(p) < 0) {
                                printf("Disconnected from %s\n", inet_ntoa(q.sin_addr));
                                remove_client(&active_clients, p->fd);
                                break;
                            }

                            // Parse the user input, which is in client.inbuf, and calculate the command length and argument length
                            char *space_ptr = strchr(p->inbuf, ' ');
                            int command_length;
                            if (space_ptr) {
                                command_length = space_ptr - p->inbuf;
                            } else {
                                command_length = strlen(p->inbuf);
                            }
                            int argument_length = strlen(p->inbuf) - command_length - 1;

                            // Execute according to the commands
                            // For a show command to be valid, the input command must match it precesely. Nothing should follow the command.
                            if (strcmp(p->inbuf, SHOW_MSG) == 0) {
                                printf("%s: %s\n", p->username, p->inbuf);
                                client_show(p);
                                
                            // For a follow command to be valid, the input command must match it precesely. Command must be followed by a non-empty argement.
                            } else if (strncmp(p->inbuf, FOLLOW_MSG, command_length) == 0 && argument_length > 0 && command_length == strlen(FOLLOW_MSG)) {
                                printf("%s: %s\n", p->username, p->inbuf);
                                client_follow(command_length, p, active_clients);

                            // For a unfollow command to be valid, the input command must match it precesely. Command must be followed by a non-empty argement.
                            } else if (strncmp(p->inbuf, UNFOLLOW_MSG, command_length) == 0 && argument_length > 0 && command_length == strlen(UNFOLLOW_MSG)) {
                                printf("%s: %s\n", p->username, p->inbuf);
                                client_unfollow(command_length, p);
                            
                            // For a send command to be valid, the input command must match it precesely. Command must be followed by a non-empty argement.
                            } else if (strncmp(p->inbuf, SEND_MSG, command_length) == 0 && argument_length > 0 && command_length == strlen(SEND_MSG)) {
                                printf("%s: %s\n", p->username, p->inbuf);
                                client_send(command_length, p);

                            // For a quit command to be valid, the input command must match it precesely. Nothing should follow the command.
                            } else if (strcmp(p->inbuf, QUIT_MSG) == 0) {
                                printf("%s: %s\n", p->username, p->inbuf);
                                remove_client(&active_clients, p->fd);
                            
                            // All other cases are considered invalid commands.
                            } else {
                                printf("Invalid command\n");
                                Write(p->fd, INVALID_COMMAND, strlen(INVALID_COMMAND), "write invalid command message to client");
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
