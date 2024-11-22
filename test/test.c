
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <stdbool.h>

#include <openssl/err.h>

#include "../proxy/proxy.h"

void test_parse_header();

int main(int argc, char* argv[]) {
    //initialize_proxy_test(9105);
    test_parse_header();

    printf("All tests Passed\n");
    return 0;
}

header_elems* proxy_parse_head(char* header)
{
    header_elems* h = (header_elems*)calloc(1,sizeof(header_elems));

    char* nl_delim = "\n";
    char* cr_delim = "\r";
    char* space_delim = " ";
    char* col_delim = ":";
    
    char* last;
    char* line = strtok_r(header, nl_delim, &last);
    printf("%s", line);
    while(strcmp(line, "\r") != 0){
        //printf("%s\n", line);
        char* inner_last;
        char* command = strtok_r(line, space_delim, &inner_last);

        if(strcmp(command, "GET") == 0 || strcmp(command, "HEAD") == 0) {
            h->url = strtok_r(NULL, space_delim, &inner_last);
            char* http_v = strtok_r(NULL, cr_delim,&inner_last);
            //printf("HTTP_v = %s\n", http_v);

        }else if(strcmp(command, "Host:") == 0) {

            h->host = strtok_r(NULL, cr_delim, &inner_last);
            if(strstr(h->host, ":") == NULL){
                h->port = "443";
            }else{
                char* host_port_delim = (strstr(h->host, ":"));
                *host_port_delim = '\0';
                h->port = host_port_delim+1;
            }
            printf("HOST = %s\n", h->host);
            printf("PORT = %s\n", h->port);

        }else if(strcmp(command, "Content-Length:") == 0) {
            char* len = strtok_r(NULL, cr_delim, &inner_last);
            h->data_len = len;

        }else if(strcmp(command, "Cache-Control:") == 0) {
            char* eq = "=";
            strtok_r(NULL, eq, &inner_last);
            //Cache-Control: max-age=N
            char* max_age = strtok(NULL, cr_delim);
            h->max_age = max_age;

        }
        line = strtok_r(NULL, "\n", &last);
    }

    return h;
}

void test_parse_header(){
    printf("starting test_parse_header test\n");
    //char* h = "HTTP/1.1 404 Not Found\r\ndate: Fri, 22 Nov 2024 01:53:45 GMT\r\nserver: mw-web.eqiad.main-5dc468848-dk4rp\r\nx-content-type-options: nosniff\r\ncontent-language: en\r\naccept-ch: \r\nvary: Accept-Encoding,Cookie,Authorization\r\ncontent-type: text/html; charset=UTF-8\r\nage: 987\r\nx-cache: cp1108 miss, cp1108 hit/2\r\nx-cache-status: hit-front\r\nserver-timing: cache;desc=\"hit-front\", host;desc=\"cp1108\"\r\nstrict-transport-security: max-age=106384710; includeSubDomains; preload\r\nreport-to: { \"group\": \"wm_nel\", \"max_age\": 604800, \"endpoints\": [{ \"url\": \"https://intake-logging.wikimedia.org/v1/events?stream=w3c.reportingapi.network_error&schema_uri=/w3c/reportingapi/network_error/1.0.0\" }] }\r\nnel: { \"report_to\": \"wm_nel\", \"max_age\": 604800, \"failure_fraction\": 0.05, \"success_fraction\": 0.0}\r\nset-cookie: WMF-Last-Access=22-Nov-2024;Path=/;HttpOnly;secure;Expires=Tue, 24 Dec 2024 00:00:00 GMT\r\nset-cookie: WMF-Last-Access-Global=22-Nov-2024;Path=/;Domain=.wikipedia.org;HttpOnly;secure;Expires=Tue, 24 Dec 2024 00:00:00 GMT\r\nx-client-ip: 173.48.230.79\r\ncache-control: private, s-maxage=0, max-age=0, must-revalidate, no-transform\r\nset-cookie: GeoIP=US:MA:Reading:42.53:-71.10:v4; Path=/; secure; Domain=.wikipedia.org\r\set-cookie: NetworkProbeLimit=0.001;Path=/;Secure;SameSite=Lax;Max-Age=3600\r\ncontent-length: 45795\r\n\r\n";
    // char http_response[] = 
    //     "HTTP/1.1 200 OK\r\n"
    //     "Date: Wed, 21 Nov 2024 10:00:00 GMT\r\n"
    //     "Server: Apache/2.4.41 (Ubuntu)\r\n"
    //     "Content-Type: text/html; charset=UTF-8\r\n"
    //     "Content-Length: 5321\r\n"
    //     "Connection: keep-alive\r\n"
    //     "Cache-Control: no-cache, no-store, must-revalidate\r\n"
    //     "Pragma: no-cache\r\n"
    //     "Expires: 0\r\n"
    //     "Last-Modified: Wed, 21 Nov 2024 09:30:00 GMT\r\n"
    //     "ETag: \"5fcb5fbb2db0b58b7f8f5e61bb0283b5\"\r\n"
    //     "Accept-Ranges: bytes\r\n"
    //     "Age: 0\r\n"
    //     "X-Frame-Options: SAMEORIGIN\r\n"
    //     "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
    //     "Content-Encoding: gzip\r\n"
    //     "Vary: Accept-Encoding\r\n"
    //     "X-Content-Type-Options: nosniff\r\n"
    //     "X-XSS-Protection: 1; mode=block\r\n"
    //     "\r\n";
    char http_response[] = "GET http://www.cs.tufts.edu/comp/112/index.html HTTP/1.1\r\nHost: www.cs.tufts.edu\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n";
    
    header_elems* e = proxy_parse_head(http_response);
    print_header_elems(e);
}

