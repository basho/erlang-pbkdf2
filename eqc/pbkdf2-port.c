#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include <openssl/evp.h>

#include <ei.h>

int main() {
	char command[4];
	int index, version, arity, type, size;
	unsigned long iterations, keylen;
	char *buf = NULL, *password = NULL, *salt = NULL, *out = NULL;
	char hash[MAXATOMLEN];
	openlog("wtf", LOG_PID, LOG_USER);
	char outbuf[1024];
	while(read(0, command, 4)) {
		unsigned int inlen = command[0] << 24 | command[1] << 16 | command[2] << 8 | command[3];
		syslog(LOG_INFO, "Got message header of length %d", inlen);
		buf = (char*)malloc(inlen+1);
		read(0, buf, inlen);
		index = 0;

		if (ei_decode_version(buf, &index, &version)) goto done;

		if (ei_decode_tuple_header(buf, &index, &arity)) goto done;

		if (arity != 5) goto done;

		if (ei_decode_atom(buf, &index, hash)) goto done;

		ei_get_type(buf, &index, &type, &size);

		if(type != 'm') goto done;
		password = (char*)malloc(size+1);
		password[size] = '\0';
		if(ei_decode_binary(buf, &index, password, (long*)&size)) goto done;

		ei_get_type(buf, &index, &type, &size);

		if(type != 'm') goto done;
		salt = (char*)malloc(size);
		if(ei_decode_binary(buf, &index, salt, (long*)&size)) goto done;
		
		if(ei_decode_ulong(buf, &index, &iterations)) goto done;
		if(ei_decode_ulong(buf, &index, &keylen)) goto done;


		syslog(LOG_INFO, "%s hashing password %s with salt %s %d times for length %d", hash, password, salt, iterations, keylen);

		out = (unsigned char *) malloc(sizeof(unsigned char) * keylen);

		syslog(LOG_INFO, "password length is %d, salt length is %d", strlen(password), size);

		if( PKCS5_PBKDF2_HMAC_SHA1(password,  strlen(password), salt, size, iterations, keylen, out) != 0 )
		{
			int i;
			unsigned char *outp = outbuf;
			for(i=0;i<keylen;i++) { sprintf(outp, "%02x", (unsigned char)out[i]); syslog(LOG_INFO, "%u -> %02x", (unsigned char)out[i], (unsigned char)out[i]); outp+=2; }
		}
		else
		{
			sprintf(outbuf, "%s", "error");
		}

		int len = strlen(outbuf);
		syslog(LOG_INFO, "output is %s of length %d", outbuf, len);
		unsigned char li;
		li = (len >> 24) & 0xff;
		write(1, &li, 1);

		li = (len >> 16) & 0xff;
		write(1, &li, 1);

		li = (len >> 8) & 0xff;
		write(1, &li, 1);

		li = len & 0xff;
		write(1, &li, 1);


		free(out);

		printf("%s", outbuf);
		fflush(stdout);
		free(buf);
		buf = NULL;
		free(password);
		password = NULL;
	}
done:
	if(buf) {
		free(buf);
	}

	if(password) {
		free(password);
	}

	return 1;
}
