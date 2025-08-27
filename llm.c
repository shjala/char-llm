/*
  LLM Character Device

  This is joke taken seriously!
*/

#define _GNU_SOURCE
#define FUSE_USE_VERSION 31

#include <fuse/cuse_lowlevel.h>
#include <fuse/fuse_opt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <curl/curl.h>
#include <pthread.h>
#include "ioctl.h"

struct curl_response {
    char *data;
    size_t size;
};

static void *llm_buf;
static size_t llm_size;
static int llm_consumed = 1;
static int llm_resize(size_t new_size);

char* escape_json_string(const char* input) {
    if (!input) return NULL;

    size_t input_len = strlen(input);
    char* escaped = malloc(input_len * 2 + 1);
    if (!escaped) return NULL;

    const char* src = input;
    char* dst = escaped;
    while (*src) {
        switch (*src) {
            case '"':
                *dst++ = '\\';
                *dst++ = '"';
                break;
            case '\\':
                *dst++ = '\\';
                *dst++ = '\\';
                break;
            case '\b':
                *dst++ = '\\';
                *dst++ = 'b';
                break;
            case '\f':
                *dst++ = '\\';
                *dst++ = 'f';
                break;
            case '\n':
                *dst++ = '\\';
                *dst++ = 'n';
                break;
            case '\r':
                *dst++ = '\\';
                *dst++ = 'r';
                break;
            case '\t':
                *dst++ = '\\';
                *dst++ = 't';
                break;
            default:
                *dst++ = *src;
                break;
        }
        src++;
    }
    *dst = '\0';

    return escaped;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, struct curl_response *response) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(response->data, response->size + realsize + 1);

    if (!ptr) {
        return 0;
    }

    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;

    return realsize;
}

char* get_content(const char* json_response) {
    const char* content_start = strstr(json_response, "\"content\":");
    if (!content_start) {
        return strdup("Error: no content found in response");
    }

    content_start += strlen("\"content\":");
    while (*content_start == ' ' || *content_start == '\t' || *content_start == '\n') {
        content_start++;
    }
    if (*content_start == '"') {
        content_start++;
    }

    const char* content_end = content_start;
    while (*content_end && *content_end != '"') {
        if (*content_end == '\\' && *(content_end + 1)) {
            content_end += 2;
        } else {
            content_end++;
        }
    }

    size_t content_len = content_end - content_start;
    char* content = malloc(content_len + 1);
    if (!content) {
        return strdup("Error: memory allocation failed");
    }

    strncpy(content, content_start, content_len);
    content[content_len] = '\0';

    /* Basic unescape for newlines */
    char* src = content;
    char* dst = content;
    while (*src) {
        if (*src == '\\' && *(src + 1) == 'n') {
            *dst = '\n';
            src += 2;
        } else if (*src == '\\' && *(src + 1) == '"') {
            *dst = '"';
            src += 2;
        } else {
            *dst = *src;
            src++;
        }
        dst++;
    }
    *dst = '\0';

    return content;
}

char* get_llm_response(const char* user_input) {
    CURL *curl;
    CURLcode res;
    struct curl_response response = {0};
    char* json_payload = NULL;
    char* escaped_input = NULL;
    char* result = NULL;

    curl = curl_easy_init();
    if (!curl) {
        return strdup("Error: failed to initialize curl");
    }

    escaped_input = escape_json_string(user_input);
    if (!escaped_input) {
        curl_easy_cleanup(curl);
        return strdup("Error: failed to escape input");
    }

    size_t payload_size = strlen(escaped_input) + 1024; /* int overflow? why not */
    json_payload = malloc(payload_size);
    if (!json_payload) {
        free(escaped_input);
        curl_easy_cleanup(curl);
        return strdup("Error: Mmmory allocation failed");
    }

    snprintf(json_payload, payload_size,
        "{"
        "\"model\":\"llama3.2:3b\","
        "\"messages\":["
        "{\"role\":\"system\",\"content\":\"You are a helpful assistant.\"},"
        "{\"role\":\"user\",\"content\":\"%s\"}"
        "]"
        "}", escaped_input);

    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:11434/v1/chat/completions");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    long response_code;
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (res != CURLE_OK) {
        result = malloc(256);
        snprintf(result, 256, "Error: curl_easy_perform() failed: %s", curl_easy_strerror(res));
    } else if (response.data) {
        result = get_content(response.data);
    } else {
        result = strdup("Error: no response received");
    }

    /* cleanup */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(json_payload);
    free(escaped_input);
    if (response.data) {
        free(response.data);
    }

    return result;
}

void process_llm_request(const char* input) {
    char* response = get_llm_response(input);
    size_t response_len = strlen(response);

    if (llm_resize(response_len + 1) == 0) {
        memcpy(llm_buf, response, response_len);
        ((char*)llm_buf)[response_len] = '\0';
        llm_consumed = 0;
    }

    free(response);
}

static int llm_resize(size_t new_size)
{
    void *new_buf;

    if (new_size == llm_size)
        return 0;

    new_buf = realloc(llm_buf, new_size);
    if (!new_buf && new_size)
        return -ENOMEM;

    if (new_size > llm_size)
        memset((char*)new_buf + llm_size, 0, new_size - llm_size);

    llm_buf = new_buf;
    llm_size = new_size;

    return 0;
}

static int llm_expand(size_t new_size)
{
    if (new_size > llm_size)
        return llm_resize(new_size);
    return 0;
}

static void llm_init(void *userdata, struct fuse_conn_info *conn)
{
    (void)userdata;
    (void)conn;
}

static void llm_open(fuse_req_t req, struct fuse_file_info *fi)
{
    fuse_reply_open(req, fi);
}

static void llm_read(fuse_req_t req, size_t size, off_t off,
         struct fuse_file_info *fi)
{
    (void)fi;

    /* if data has been consumed or reading beyond buffer, return EOF */
    if (llm_consumed || off >= (off_t)llm_size) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    if (size > llm_size - off)
        size = llm_size - off;

    /* mark as consumed after first read */
    llm_consumed = 1;
    fuse_reply_buf(req, (char*)llm_buf + off, size);
}

static void llm_write(fuse_req_t req, const char *buf, size_t size,
              off_t off, struct fuse_file_info *fi)
{
    (void)fi;
    (void)off;

    if (llm_expand(size + 1)) {
        fuse_reply_err(req, ENOMEM);
        return;
    }

    char* user_input = malloc(size + 1);
    if (!user_input) {
        fuse_reply_err(req, ENOMEM);
        return;
    }

    memcpy(user_input, buf, size);
    user_input[size] = '\0';

    process_llm_request(user_input);
    free(user_input);

    fuse_reply_write(req, size);
}

static void llm_ioctl(fuse_req_t req, int cmd, void *arg,
              struct fuse_file_info *fi, unsigned flags,
              const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
    (void)fi;
    (void)arg;
    (void)flags;
    (void)in_buf;
    (void)in_bufsz;
    (void)out_bufsz;

    fuse_reply_err(req, EINVAL);
}

static const struct cuse_lowlevel_ops llm_clop = {
    .init       = llm_init,
    .open       = llm_open,
    .read       = llm_read,
    .write      = llm_write,
    .ioctl      = llm_ioctl,
};

int main(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    char dev_name[128] = "DEVNAME=llm";
    const char *dev_info_argv[] = { dev_name };
    struct cuse_info ci;

    memset(&ci, 0, sizeof(ci));
    ci.dev_major = 0;
    ci.dev_minor = 0;
    ci.dev_info_argc = 1;
    ci.dev_info_argv = dev_info_argv;
    ci.flags = CUSE_UNRESTRICTED_IOCTL;

    /* init the size and buffer */
    if (llm_resize(1024) != 0) {
        fprintf(stderr, "Failed to initialize buffer\n");
        curl_global_cleanup();
        return 1;
    }

    const char* welcome_msg = "LLM Character Device Ready\n";
    size_t welcome_len = strlen(welcome_msg);
    if (welcome_len < llm_size) {
        memcpy(llm_buf, welcome_msg, welcome_len);
        ((char*)llm_buf)[welcome_len] = '\0';
    }

    /* init curl */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* mark as not consumed initially */
    llm_consumed = 0;
    int result = cuse_lowlevel_main(args.argc, args.argv, &ci, &llm_clop, NULL);

    /* cleanup */
    curl_global_cleanup();
    if (llm_buf) {
        free(llm_buf);
    }

    return result;
}
