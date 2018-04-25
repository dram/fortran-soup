#include <libsoup/soup.h>
#include <stdio.h>

#define INT_PARAMETER "integer(c_int), parameter :: "

int main(void)
{
	printf(INT_PARAMETER
	       "soup_request_error_bad_uri = %d\n",
	       SOUP_REQUEST_ERROR_BAD_URI);

	return 0;
}
