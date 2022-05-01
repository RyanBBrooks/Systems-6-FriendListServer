/*
 * friendlist.c - [Starting code for] a web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

static void *doit(void *fd_p);
static dictionary_t *read_requesthdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum, 
                        char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);

static void serve_request(int fd, char *body);
static void add_user(char* user);
static void change_friendship(char* user, char* friends, int befriend);
static void req_friends(int fd, dictionary_t *query);
static void req_change_friendship(int fd, dictionary_t *query, int befriend);
static void req_introduce(int fd, dictionary_t *query);

static dictionary_t *dict;
sem_t dict_sem;

int main(int argc, char **argv) {
  int listenfd, connfd, *connfd_p;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  pthread_t th;
  struct sockaddr_storage clientaddr;
  
  /* create dictionary */
  dict = make_dictionary(COMPARE_CASE_SENS, NULL);

  /* Check command line args */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  /* initialize semaphore */
  Sem_init(&dict_sem, 0 ,1);

  listenfd = Open_listenfd(argv[1]);

  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);

  while (1) {
    clientlen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);

    Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, 
                  port, MAXLINE, 0);
    printf("Accepted connection from (%s, %s)\n", hostname, port);
    
    connfd_p = malloc(sizeof(int));
    *connfd_p = connfd;
    Pthread_create(&th, NULL, doit, connfd_p);
    Pthread_detach(th);
    //doit(connfd);
    //Close(connfd);
    
  }
}

/*
 * doit - handle one HTTP request/response transaction
 */
void *doit(void *fd_p) {
  int fd = *(int *)fd_p;
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return NULL;
  printf("%s", buf);
  
  if (!parse_request_line(buf, &method, &uri, &version)) {
    clienterror(fd, method, "400", "Bad Request",
                "Friendlist did not recognize the request");
  } else {
    if (strcasecmp(version, "HTTP/1.0")
        && strcasecmp(version, "HTTP/1.1")) {
      clienterror(fd, version, "501", "Not Implemented",
                  "Friendlist does not implement that version");
    } else if (strcasecmp(method, "GET")
               && strcasecmp(method, "POST")) {
      clienterror(fd, method, "501", "Not Implemented",
                  "Friendlist does not implement that method");
    } else {
      headers = read_requesthdrs(&rio);

      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST"))
        read_postquery(&rio, headers, query);

      /* For debugging, print the dictionary */
      print_stringdictionary(query);

      /* request name */
      char* request =split_string(uri,'?')[0];

      /* friends */
      if(!strcmp(request,"/friends")){
	req_friends(fd,query);
      }
      /* befriend */
      else if(!strcmp(request,"/befriend")){
	req_change_friendship(fd,query,1);
      }
      /* unfriend*/
      else if(!strcmp(request,"/unfriend")){
	req_change_friendship(fd,query,0);
      }
      /* introduce*/
      else if(!strcmp(request,"/introduce")){
	req_introduce(fd,query);
      }
      /* You'll want to handle different queries here,
         but the intial implementation always returns
         nothing: */
      
      else{
	//shouldnt get here
	serve_request(fd,"");
      }
      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
    }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }
  Close(fd);
  return NULL;
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp) {
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while(strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }
    
  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest) {
  char *len_str, *type, *buffer;
  int len;
  
  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");
  
  buffer = malloc(len+1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded")) {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type) {
  char *len_str, *header;
  
  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: Friendlist Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

static void add_user(char *user){
  dictionary_set(dict,user,make_dictionary(COMPARE_CASE_SENS, NULL)); 
}

static void req_friends(int fd, dictionary_t *query){
  char *body, *user;
  dictionary_t *d;
  
  body = "";
  /* if user exists */
  if((user = dictionary_get(query,"user"))!=NULL){    
    /* if in dict */
    P(&dict_sem);
    if((d = dictionary_get(dict,user))!=NULL){
      /* add all friends to body */
      body =  join_strings(dictionary_keys(d), '\n');
    }
    /* create the user */
    else{
      add_user(user);
    }
    V(&dict_sem);
  }
  serve_request(fd,body);
}

static void change_friendship(char* user, char* friends, int befriend){
  dictionary_t *d;
  char **all_friends;
  /* if user not in dict */
  P(&dict_sem);
  if((d = dictionary_get(dict,user))==NULL){
    /* setup user entry */
    add_user(user);
    d = dictionary_get(dict,user);
  }
  /* separate friends */
  all_friends=split_string(friends,'\n');
  int i=0;
  /* for every friend in friends */
  while(all_friends[i]!=NULL){
    char *curr = strdup(all_friends[i]);
    /* if user equals friend dont add*/
    if(!strcmp(user,curr)){
      i++;
      continue;
    }
    dictionary_t *curr_d;
    /* if friend not in dict */
    if((curr_d = dictionary_get(dict,curr))==NULL){
      /* setup friend entry */
      add_user(curr);
      curr_d = dictionary_get(dict,curr);
    }
    /*add to opposing dictionaries*/
    if(befriend){
      dictionary_set(d,curr,NULL);
      dictionary_set(curr_d,user,NULL);
    }
    /* remove friend */
    else{
      dictionary_remove(d,curr);
      dictionary_remove(curr_d,user);
    }
    /* increment */
    i++;
  }
  V(&dict_sem);
}

static void req_change_friendship(int fd, dictionary_t *query, int befriend){
  char *user, *friends;
  /* if user exists and friends exists*/
  if((user=dictionary_get(query,"user"))!=NULL && (friends=dictionary_get(query,"friends"))!=NULL){
    change_friendship(user,friends,befriend);
    req_friends(fd, query);
  }
}


static void req_introduce(int fd, dictionary_t *query){
  char *user, *friend, *host, *port, *request;
  int len;

  /* if user exists and friend exists and port exists and host exists*/
  if((user=dictionary_get(query,"user"))!=NULL && (friend=dictionary_get(query,"friend"))!=NULL &&
     (host=dictionary_get(query,"host"))!=NULL && (port=dictionary_get(query,"port"))!=NULL ){
    /* request server for list */
    int _fd = open_clientfd(host,port);
    char buf[MAXLINE];
    rio_t rio;
    size_t n;
    /*create request*/
    request = append_strings("GET /friends?user=", friend,
			     " HTTP/1.0\r\nHost: ", host, ":", port, 
			     "\r\nContent-Length: 0\r\n\r\n");
    len = strlen(request);

    Rio_writen(_fd,request,len);


    Rio_readinitb(&rio, _fd);
    /* find body */
    while((n = Rio_readlineb(&rio, buf, MAXLINE))!=0){
      if(!strcmp(buf,"\r\n")){
	break;
      }
    }
    /* add friends of friend */
    while((n = Rio_readlineb(&rio, buf, MAXLINE))!=0){
      char *name = split_string(buf,'\n')[0];
      change_friendship(user,name,1);
    }
  }
  /*update for friend itself*/
  Close(_fd);
  change_friendship(user,friend,1);
  serve_request(fd,"");
}


/*
 * serve_request - example request handler
 */
static void serve_request(int fd, char *body) {
  size_t len;
  char *header;

  body = strdup(body);
  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg) {
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Friendlist Error</title>",
                        "<body bgcolor=""ffffff"">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>Friendlist Server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);
  
  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d) {
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++) {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}
