#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

char *helper_login_register() 
{
    char *username = calloc(REG, sizeof(char));
    char *password = calloc(REG, sizeof(char));

    // register/login user
    printf("username=");
    fgets(username, COMM_LEN, stdin);
    printf("password=");
    fgets(password, COMM_LEN, stdin);

    // JSON parsing
    JSON_Value *value = json_value_init_object();
    JSON_Object *object = json_value_get_object(value);
    json_object_set_string(object, "username", username);
    json_object_set_string(object, "password", password);
    char *x = json_serialize_to_string_pretty(value);

    free(username);
    free(password);
    return x;
}

char *helper_add_book()
{
    char *title = calloc(COMM_LEN, sizeof(char));
    char *author = calloc(COMM_LEN, sizeof(char));
    char *genre = calloc(COMM_LEN, sizeof(char));
    char *publisher = calloc(COMM_LEN, sizeof(char));
    char *page_count = calloc(COMM_LEN, sizeof(char));
    
    // get information about book added
    printf("title=");
    fgets(title, COMM_LEN, stdin);
    printf("author=");
    fgets(author, COMM_LEN, stdin);
    printf("publisher=");
    fgets(publisher, COMM_LEN, stdin);
    printf("genre=");
    fgets(genre, COMM_LEN, stdin);
    printf("page_count=");
    fgets(page_count, COMM_LEN, stdin);
    
    // if has negative number of pages in not valid
    if (atoi(page_count) <= 0) {
        printf("Invalid number of pages!\n");
        return NULL;
    }
    
    // JSON parsings
    JSON_Value *value = json_value_init_object();
    JSON_Object *object = json_value_get_object(value);
    json_object_set_string(object, "title", title);
    json_object_set_string(object, "author", author);
    json_object_set_string(object, "genre", genre);
    json_object_set_string(object, "page_count", page_count);
    json_object_set_string(object, "publisher", publisher);

    char *x = json_serialize_to_string_pretty(value);

    free(title);
    free(author);
    free(genre);
    free(page_count);
    free(publisher);

    return x;
} 
void registerUser(char *host_api, char *content_type, char *response, int sockfd,
    char *message)
{
    char *json = helper_login_register();
    char *url_register = "/api/v1/tema/auth/register";
    char *json_response = calloc(COMM_LEN, sizeof(char));

    // compute message, send it and receive response
    message = compute_post_request(host_api, url_register, content_type,
        &json, 1, NULL, 0, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    json_response = basic_extract_json_response(response);

    if (json_response == NULL) {
        printf("Registration successful!\n");
    } else {
        printf("The username is taken!\n");
        free(json_response);
    }

    free(json);
}

char* loginUser(char *host_api, char *content_type, int sockfd,
    char *response, char *message)
{
    char *json = helper_login_register();
    char *url_login = "/api/v1/tema/auth/login";
    char *cookie = calloc(MESS_LEN, sizeof(char));
    char *json_response = calloc(COMM_LEN, sizeof(char));

    message = compute_post_request(host_api, url_login, content_type,
        &json, 1, NULL, 0, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    json_response = basic_extract_json_response(response);

    // keep the cookie
    if (json_response == NULL) {
        printf("Login successful!\n");
        char *aux = strstr(response, "connect");
        char *junk = calloc(MESS_LEN, sizeof(char));
        sscanf(aux, "%s;%s;", cookie, junk);
        cookie[strlen(cookie) - 1] = 0;
    } else {
        printf("The credentials are incorrect!\n");
        free(json_response);
    }

    free(json);

    return cookie;
}

char* enterLibrary(char *host_api, char *cookie, int sockfd,
    char *message, char *response)
{
    char *token = calloc(MESS_LEN, sizeof(char));
    char *url_enter_library = "/api/v1/tema/library/access";
    char *json_response = calloc(MESS_LEN, sizeof(char));

    message = compute_get_request(host_api, url_enter_library, NULL,
        &cookie, 1, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    json_response = basic_extract_json_response(response);
    char *aux1 = strstr(json_response, "error");

    // did't find any error
    if (aux1 == NULL) {
        printf("Entering library successful!\n");
        char *aux2 = strstr(json_response, "token");
        char *junk = calloc(MESS_LEN, sizeof(char));
        char *content_all = calloc(MESS_LEN, sizeof(char));
        sscanf(aux2, "%[^'\"']%s", junk, content_all);
        token = content_all + 3;
        token[strlen(token) - 2] = 0;
        free(aux1);
    } else {
        printf("You are not logged in!\n");
    }

    return token;
}

int addBooks(char *message, char *host_api, char *content_type, int sockfd,
    char *response, char *cookie, char *token)
{
    char *json = helper_add_book();
    
    // couldn't create book, try again
    if (json == NULL) {
        return 1;
    // try to put book in library
    } else {
        char *json_response = calloc(COMM_LEN, sizeof(char));
        char *url_add_book = "/api/v1/tema/library/books";
        message = compute_post_request(host_api, url_add_book, content_type,
            &json, 1, &cookie, 1, token);
        send_to_server(sockfd, message);
        response = receive_from_server(sockfd);
        json_response = basic_extract_json_response(response);
        if (json_response == NULL) {
            printf("Adding book successful!\n");
        } else {
            printf("You are not logged in library!\n");
        }
        free(json);
    }
    
    return 0;
}

void getBooks(char *message, char *host_api, char *cookie, char *token,
    int sockfd, char *response)
{
    char *url_get_books = "/api/v1/tema/library/books";
    char *json_response = calloc(MESS_LEN, sizeof(char));
    message = compute_get_request(host_api, url_get_books, NULL,
        &cookie, 1, token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    json_response = basic_extract_json_response(response);
    char *aux = strstr(json_response, "error");
    if (aux == NULL) {
        printf("The books are:\n");
        printf("%s\n", json_response);
    } else {
        printf("You are not logged in library!\n");
    }
}

void getBookID(char *message, char*host_api, char *cookie, char *token,
    char *response, int sockfd)
{
    char *url_get_book = "/api/v1/tema/library/books";
    char *new_url_get_book = calloc(COMM_LEN, sizeof(char));
    char *id = calloc(COMM_LEN, sizeof(char));
    char *json_response = calloc(MESS_LEN, sizeof(char));

    // get id from stdin
    printf("id=");
    fgets(id, COMM_LEN, stdin);
    id[strlen(id) - 1] = 0;

    // make new url from the old one concatenating '/id'
    strcpy(new_url_get_book, url_get_book);
    strcat(new_url_get_book, "/");
    strcat(new_url_get_book, id);

    message = compute_get_request(host_api, new_url_get_book, NULL,
        &cookie, 1, token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    json_response = basic_extract_json_response(response);

    char *aux1 = strstr(json_response, "error");
    if (aux1 == NULL) {
        printf("The books is:\n");
        printf("%s\n", json_response);
    } else {  
        char *aux2 = strstr(json_response, "tokenn");           	
        if (aux2 == NULL) {
            printf("There is no book with this id!\n");
        } else {
            printf("You are not logged in library!\n");
        }
    }

    free(new_url_get_book);
    free(id);
}

void deleteBookID(char *message, char *host_api, char *cookie, char *token,
    int sockfd, char *response)
{
    char *url_delete_book = "/api/v1/tema/library/books";
    char *new_url_delete_book = calloc(COMM_LEN, sizeof(char));
    char *id = calloc(COMM_LEN, sizeof(char));
    char *json_response = calloc(MESS_LEN, sizeof(char));

    printf("id=");
    fgets(id, COMM_LEN, stdin);
    id[strlen(id) - 1] = 0;

    strcpy(new_url_delete_book, url_delete_book);
    strcat(new_url_delete_book, "/");
    strcat(new_url_delete_book, id);

    message = compute_delete_request(host_api, new_url_delete_book, NULL,
        &cookie, 1, token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    json_response = basic_extract_json_response(response);

    if (json_response == NULL) {
        printf("Book deleted!\n");	
    } else {  
        char *aux = strstr(json_response, "tokenn");           	
        if (aux == NULL) {
            printf("There is no book with this id!\n");
        } else {
            printf("You are not logged in library!\n");
        }
    }

    free(new_url_delete_book);
    free(id);
}

void logoutUser(char *message, char *host_api, char *cookie, char *token,
    int sockfd, char *response)
{
    char *url_logout = "/api/v1/tema/auth/logout";
    char *json_response = calloc(MESS_LEN, sizeof(char));
    message = compute_get_request(host_api, url_logout, NULL,
        &cookie, 1, token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    json_response = basic_extract_json_response(response);

    if (json_response == NULL) {
        printf("You are now logged out!\n");
        strcpy(cookie, " ");
        strcpy(token, " ");
    } else {
        printf("You are not logged in!\n");
    }

}
int main(int argc, char *argv[])
{
    char *message = calloc(MESS_LEN, sizeof(char));
    char *command = calloc(COMM_LEN, sizeof(char));
    char *response = calloc(MESS_LEN, sizeof(char));
    char *host_api = "34.241.4.235";
    int portno = 8080;
    char *content_type = "application/json";
    char *cookie = calloc(MESS_LEN, sizeof(char));
    char *token = calloc(MESS_LEN, sizeof(char));
    int sockfd;
    printf("\nPlease insert one of this commands:\n");
    printf("register\n");
    printf("login\n");
    printf("enter_library\n");
    printf("get_books\n");
    printf("get_book\n");
    printf("add_book\n");
    printf("delete_book\n");
    printf("logout\n");
    printf("exit\n\n");

    fgets(command, COMM_LEN, stdin);

    while (strncmp(command, "exit", 4) != 0) {
        // for every command, open connection
        sockfd = open_connection(host_api, portno, AF_INET, SOCK_STREAM, 0);

        if (strncmp(command, "register", 8) == 0) {
            registerUser(host_api, content_type, response, sockfd, message);
        } else if (strncmp(command, "login", 5) == 0) {
            cookie = loginUser(host_api, content_type, sockfd, response,
                message);
        } else if (strncmp(command, "enter_library", 13) == 0) {
            token = enterLibrary(host_api, cookie, sockfd, message, response);
        } else if (strncmp(command, "add_book", 8) == 0) {
            int ok = addBooks(message, host_api, content_type, sockfd,
                response, cookie, token);
            // if the data was incorrect, try again
            if (ok == 1) {
                continue;
            }
        } else if (strncmp(command, "get_books", 9) == 0) {
            getBooks(message, host_api, cookie, token, sockfd, response);
        } else if (strncmp(command, "get_book", 8) == 0) {
            getBookID(message, host_api, cookie, token, response, sockfd);
        } else if (strncmp(command, "delete_book", 11) == 0) {
            deleteBookID(message, host_api, cookie, token, sockfd, response);
        } else if (strncmp(command, "logout", 6) == 0) {
            logoutUser(message, host_api, cookie, token, sockfd, response);
        } else {
            printf("Invalid command!\n");
        }
        close(sockfd);
        fgets(command, COMM_LEN, stdin);
    }

    // free all memory before leaving program
    free(message);
    free(command);
    free(response);
    free(cookie);
    free(token);

    return 0;
}
