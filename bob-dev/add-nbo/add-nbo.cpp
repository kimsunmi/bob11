#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

int main(int argc, char **argv){
	//FILE* fp = fopen("thousand.bin","rb");
	uint32_t n1,n2,n3;
	FILE *fp1, *fp2;
	
	fp1 = fopen(argv[1],"rb");
	fp2 = fopen(argv[2],"rb");
	
	fread(&n1,sizeof(uint32_t),1,fp1);
		
	//fopen("five-hundred.bin","rb");
	fread(&n2,sizeof(uint32_t),1,fp2);
	//printf("%x + %x = %x\n",n1,n2,n1+n2);
	//printf("%x %x\n",n1,n2);
	
	n1 = ntohl(n1);
	n2 = ntohl(n2);

	n3 = n1 + n2;

	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)",n1,n1,n2,n2,n3,n3);
	
	fclose(fp1);
	fclose(fp2);
}

