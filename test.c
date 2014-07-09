#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>


#include "common.h"
#include "crypto.h"
#include "log.h"

int parse_config_file(const char *file_name)
{
	int fd, ret;
	struct json_tokener *tok;
	struct json_object *parent;
	char buff[1024];

	fd = open(file_name, O_RDONLY);
	if (fd == -1) {
		pr_warn("%s: %s\n", __func__, strerror(errno));
		return -1;
	}

	ret = read(fd, buff, 1024);
	if (ret == -1) {
		pr_warn("%s: %s\n", __func__, strerror(errno));
		return -1;
	}

	tok = json_tokener_new();
	if (tok == NULL) {
		pr_warn("%s: json_tokener_new error\n", __func__);
		return -1;
	}

	parent = json_tokener_parse_ex(tok, buff, ret);
	ret = json_tokener_get_error(tok);
	if (ret != json_tokener_success) {
		pr_warn("%s: %s\n", __func__, json_tokener_error_desc(ret));
		return -1;
	}

	json_object_object_foreach(parent, key, child) {
		printf("key: %s\n", key);
		printf("value: %s\n",
		       json_object_to_json_string_ext(child,
						      JSON_C_TO_STRING_PLAIN));
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	ret = parse_config_file(argv[1]);
	if (ret != 0)
		exit(1);

	return 0;
}
