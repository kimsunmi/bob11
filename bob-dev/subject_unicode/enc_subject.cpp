#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
 
using namespace std;

int main(){
 
    //파일을 읽어와서 새로운 텍스트로 작성
    ifstream fin("context.enc");
    ofstream fout("context_result.txt");

    // 파일을 읽어서 담을 변수
    char buf[1000000];

    // 인코딩 포맷
    // utf-8 = "\xEF\xBB\xBF";
    // utf-16 = "\xFF\xFE";
    // utf-32 = "\xFF\xFE\x00\x00";
    // euc-kr의 경우 파이썬으로 지정해서 풀이 or 인코딩 사이트 참고

    // 파일의 bom을 utf-32로 지정하기 위한 변수
    char encformat[1000000] = "\xFF\xFE\x00\x00";

    //seekg()를 이용하여 파일의 마지막으로 포인터를 옮긴다.
    fin.seekg(0, ios::end);
    
    //tellg()를 이용하여 파일의 사이즈를 구한다.
    int sz = fin.tellg();

    //seekg()를 이용하여 다시 파일의 처음으로 포인터를 옮긴다.
    fin.seekg(0, ios::beg);
 
    //binary로 파일을 읽을 때는 read함수로 읽는다.
    fin.read(buf, sz);
    
    // 파일 내용 사이즈 확인 출력
    // cout << sz << endl;
    
    int sz2=strlen(encformat);

    // encformat(bom)을 buf 앞에 붙여 encformat 변수에 저장한다.
    memmove(encformat+sz2, buf, sizeof(char) * sz);
    cout << sz2 << endl;
    sz2=strlen(encformat)+sz;

    // file 생성하여 buf 내용 작성 (파일의 bom과 이후 파일 내용이 작성됨)
    fout.write(encformat, sz2);
    fout.close();
    return 0;
}
