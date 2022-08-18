#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char* argv[]) {
	FILE *fp;

	uint8_t ptr[4]={0,};
	long long offset_start=0,offset_end=0;
	fp = fopen(argv[1], "rb");

	// sector 0,1 pass
	for(int i=0;i<256;i++){
		fread(&ptr, sizeof(uint32_t),1,fp);
	}
	
	fread(&ptr,sizeof(uint32_t),1,fp);
	// sector 2 read start 4byte
	// print GUID
	while(ptr[0]!=0 && ptr[1]!=0 && ptr[2]!=0){

		for(int i=4; i>0; i--){
			printf("%X",ptr[i-1]);
		}
		printf("-");	
		fread(&ptr,sizeof(uint32_t),1,fp);	
		printf("%X%X-%X%X",ptr[1],ptr[0],ptr[3],ptr[2]);
	
		printf("-");
	
		fread(&ptr,sizeof(uint32_t),1,fp);
		printf("%X%X-%X%X",ptr[0],ptr[1],ptr[2],ptr[3]);
	
		fread(&ptr,sizeof(uint32_t),1,fp);
		for(int i=0; i<4; i++){
			printf("%X",ptr[i]);
		}


		printf(" ");
	
		// read offset sector	
		// jump 16 byte
		for(int i=0; i<4; i++){
			fread(&ptr,sizeof(uint32_t),1,fp);
		}
	
		fread(&offset_start,sizeof(uint32_t),2,fp);
		printf(" %d", offset_start*512);
		fread(&offset_end, sizeof(uint32_t),2,fp);
		printf(" %d\n", (offset_end-offset_start)+1);
		
		for(int i=0;i<20;i++){
			fread(&ptr,sizeof(uint32_t),1,fp);			
		}
		
		fread(&ptr,sizeof(uint32_t),1,fp);
	}
	
	fclose(fp);
	return 0 ;
	
}
