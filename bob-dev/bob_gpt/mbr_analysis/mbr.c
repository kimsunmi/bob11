#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char* argv[]) {
	FILE *fp;
	// 4byte type
	uint8_t ptr[4]={0,};
	
	// 8byte type
	long long ebr_start=0,ebr_end=1, vbr_start=0, vbr_size=0, base_ebr=0;
	
	fp = fopen(argv[1], "rb");

	// mbr
	for(int i=0;i<111;i++){
		fread(&ptr, sizeof(uint32_t),1,fp);
	}
	fread(&ptr, sizeof(uint8_t),1,fp);
	fread(&ptr, sizeof(uint8_t),1,fp);
	// end mbr boot code
	
	
	for (int i=0;i<3;i++){
		fread(&ptr, sizeof(uint32_t),1,fp);
		//read filesystem(0) + chs address (3)
		fread(&ptr, sizeof(uint32_t),1,fp);
		
		// !file sys -> end mbr 
		if(ptr[0]==0) break;
		if(ptr[0]==7){
			printf("NTFS ");
		}
		//read lba address of start
		fread(&vbr_start, sizeof(uint32_t),1,fp);
		
		// pysical sector
		printf("%d ",vbr_start);
		
		//read number of sectors
		fread(&vbr_size, sizeof(uint32_t),1,fp);
		
		// partition size
		printf("%d\n",vbr_size*512);
	}
	
	fread(&ptr, sizeof(uint32_t),1,fp);
	//read filesystem(0) + chs address (3)
	fread(&ptr, sizeof(uint32_t),1,fp);
	fread(&ebr_start, sizeof(uint32_t),1,fp);
	if(ebr_start == 0) return 0;
	fread(&ebr_end, sizeof(uint32_t),1,fp);
	fread(&ptr, sizeof(uint8_t),1,fp);
	fread(&ptr, sizeof(uint8_t),1,fp);
	// end mbr section
	
	vbr_start=0;
	base_ebr=ebr_start;
	for(int i=0;i<3;i++){
		
		fseek(fp,(ebr_start*512+0x1BE),SEEK_SET);
		// printf("%x ->",(ebr_start+vbr_start)*512+0x1BE);
		fread(&ptr, sizeof(uint32_t),1,fp);
		fread(&ptr, sizeof(uint32_t),1,fp);
		
		
		fread(&vbr_start, sizeof(uint32_t),1,fp);
		// pysical sector
		if(vbr_start==0) break;
		if(ptr[0]==7){
			printf("NTFS ");
		}
		printf("%d ",(vbr_start+ebr_start));
		//read number of sectors
		fread(&vbr_size, sizeof(uint32_t),1,fp);
		// partition size
		
		printf("%d\n",vbr_size*512);
		
		fread(&ptr, sizeof(uint32_t),1,fp);
		fread(&ptr, sizeof(uint32_t),1,fp);
		fread(&vbr_start, sizeof(uint32_t),1,fp);
		ebr_start = base_ebr + vbr_start;

	}
	
	fclose(fp);
	return 0 ;
}
