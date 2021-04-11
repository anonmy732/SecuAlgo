#include <stdio.h>

typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned int WORD;
#define BLOCK_SIZE 8
#define DES_ROUND 16

/*
* 헤더파이롤 저장하는 것이 오히려 좋은 변수들 
*/

//전치 순열이 들어가 있는 코드
BYTE ip[64] =
{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};
BYTE inv_ip[64] =
{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25
};
// F함수 내 확장 전치 순열이 들어가 있는 코드
BYTE E[48] =
{
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8 , 9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};
// 8개의 s_box가 들어있는 코드 [S-box종류][행][열]
BYTE s_box[8][2][4] =
{
	{ { 14,  4, 13,  1 }, {  2, 15, 11,  8 } },
	{ {  3, 10,  6, 12 }, {  5,  9,  0,  7 } },
	{ {  0, 15,  7,  4 }, { 14,  2, 13,  1 } },
	{ { 10,  6, 12, 11 }, {  9,  5,  3,  8 } },
	{ {  4,  1, 14,  8 }, { 13,  6,  2, 11 } },
	{ { 15, 12,  9,  7 }, {  3, 10,  5,  0 } },
	{ { 15, 12,  8,  2 }, {  4,  9,  1,  7 } },
	{ {  5, 11,  3, 14 }, { 10,  0,  6, 13 } }
};

BYTE pc2_table[] =
{
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42 ,50 ,36, 29, 32
}

// 매크로/인라인 함수 // Bug 주의, 동작 확인 필요!
inline swap(UINT *L, UINT *R) {
	UINT t = *L;
	*L = *R;
	*R = t;
}
inline BtoW(BYTE D[], UINT* L, UINT* R) {
	*L = 0, * R = 0;
	for (int i = 7; i >= 4; i--)
		*L += *(D + i) << sizeof(BYTE) * (i - 4);
	for (int i = 3; i >= 0; i++)
		*R += *(D + i) << sizeof(BYTE) * i;
}
inline WtoB(UINT L, UINT R, BYTE D[]) {
	for (int i = 3; i >= 0; i++)
		D[i + 4] = L >> 2 * i & 0xFF;
	for (int i = 3; i >= 0; i++)
		D[i] = R >> 2 * i & 0xFF;
}

//함수 정의
void DES_Encryption(BYTE* p_text, BYTE* result, BYTE* key);
void IP(BYTE* in, BYTE* out);
void inv_IP(BYTE* in, BYTE* out);
UINT f(UINT r, BYTE* rkey);
void EP(UINT r, BYTE* out);
UINT S_box_Transfer(BYTE* in);
void key_expansion(BYTE* key, BYTE round_key[16][6]);
UINT cir_shift(UINT n, int r);

//Permutation(S_box_Transfer(data));
//PC1(key, pc1_result);
//makeBit28(&c, &d, pc1_result);
//PC2(c, d, round_key[i]);

// main 함수: 역할 적기
int main() {

	BYTE plain[] = { 0, };			//평문 

	printf("평문입력 : ");
	scanf_s("%s", plain);

	int i = 0;
	//compress PC2 함수 (56비트를 48비트로 변경
	for (i = 0; i < 48; i++)
	{
		out_data[i] = in_data[pc2_table[i] - 1];
	}

	// ip -> 64의 입력을 받아 64개의 흐트러진 출력을 받는 것
	for (i = 0; i < 64; i++)
	{
		out_data[i] = in_data[ip[i] - 1];
	}

	//확장함수 32비트를 48비트로 변경
	for (i = 0; i < 48; i++)
	{
		out_data[i] = in_data[expand_table[i] - 1];
	}
	// 1. input
	// 2. initial permutation --> IP함수
	// 3. Des_Encryption 함수
	//    3-1. Key Scheduling
	//    3-2. 16 Round 반복
	//         L, R 쪼개고, 회전함수(확장R, 보조키Ki) 연산 등
	// 4. inverse intial permutation --> inv_IP함수
	// 5. output

	return 0;
}

// 암호화 코드
void DES_Encryption(BYTE* p_text, BYTE* result, BYTE* key) {
	int i;
	BYTE data[BLOCK_SIZE] = { 0, };

	BYTE round_key[16][6] = { 0, };
	UINT left = 0, right = 0;

	IP(p_text, data);						// 초기 전치
	key_expansion(key, round_key);			// 키 확장

	BtoW(data, &left, &right);				// 32비트씩 쪼갬

	for (i = 0; i < DES_ROUND; i++) {
		left = left ^ f(right, round_key[i]);
		if (i != DES_ROUND - 1)
			swap(&left, &right);			//L과 R 값 swap
	}

	WtoB(left, right, data);
	inv_IP(data, result);                    // 마지막 전치
}

// 초기 전치코드
void IP(BYTE* in, BYTE* out)
{
	int i;
	BYTE index, bit, mask = 0x80;

	for (i = 0; i < 64; i++)
	{
		index = (ip[i] - 1) / 8;
		bit = (ip[i] - 1) % 8;

		if (in[index] & (mask >> bit))
			out[i / 8] |= mask >> (i % 8);
	}
}

// 초기 전치코드 역함수	// **Note** Bug 주의 동작확인 필요!
void inv_IP(BYTE* in, BYTE* out)
{
	int i;
	BYTE index, bit, mask = 0x80;

	for (i = 0; i < 64; i++)
	{
		index = (inv_ip[i] - 1) / 8;
		bit = (inv_ip[i] - 1) % 8;

		if (in[index] & (mask >> bit))
			out[i / 8] |= mask >> (i % 8);
	}
}

// F함수 코드
UINT f(UINT r, BYTE* rkey)
{
	int i;
	BYTE data[6] = { 0, };
	UINT out;

	EP(r, data);

	for (i = 0; i < 6; i++)                                 // 라운드 키와 xor
		data[i] = data[i] ^ rkey[i];

	out = Permutation(S_box_Transfer(data));   // S박스 통과하여 전치함		// **Note** 고쳐야 함 -> 함수추가

	return out;
}

// F함수 내 확장 전치 코드
void EP(UINT r, BYTE* out)
{
	int i;
	UINT mask = 0x80000000;

	for (i = 0; i < 48; i++)
	{
		if (r & (mask >> (E[i] - 1)))
		{
			out[i / 8] |= (BYTE)(0x80 >> (i % 8));
		}
	}
}

// S-box 코드
UINT S_box_Transfer(BYTE* in)
{
	int i, row, column, shift = 28;
	UINT temp = 0, result = 0, mask = 0x80;

	for (i = 0; i < 48; i++)
	{
		if (in[i / 8] & (BYTE)(mask >> (i % 8)))  // 마스크를 씌워 확인 후 temp에 해당 비트 1로 함
			temp |= 0x20 >> (i % 6);

		if ((i + 1) % 6 == 0)                        // 6비트마다
		{
			row = ((temp & 0x20) >> 4) + (temp & 0x01);           // 행 값
			column = (temp & 0x1E) >> 1;                               // 열 값

			result += ((UINT)s_box[i / 6][row][column] << shift);    // 값 더하고 쉬프트(4비트씩)

			shift -= 4;
			temp = 0;
		}
	}

	return result;
}

// 키 확장 코드
void key_expansion(BYTE* key, BYTE round_key[16][6])
{
	int i;
	BYTE pc1_result[7] = { 0, };
	UINT c = 0, d = 0;

	PC1(key, pc1_result);                // 축소 전치(64 -> 56)  // **Note** 고쳐야 함 함수 추가 선언

	makeBit28(&c, &d, pc1_result);  // 28비트씩 쪼갬  // **Note** 고쳐야 함 함수 추가 선언

	for (i = 0; i < 16; i++)
	{
		c = cir_shift(c, i);             // 순환왼쪽쉬프트
		d = cir_shift(d, i);

		PC2(c, d, round_key[i]);     // 축소 전치(56 -> 48)  // **Note** 고쳐야 함 함수 추가 선언
	}
}

// 왼쪽 순환 쉬프트 코드
UINT cir_shift(UINT n, int r)
{
	int n_shift[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

	n = (n << n_shift[r]) + (n >> (28 - n_shift[r]));

	return n & 0xFFFFFFF;      // 쓰레기값 제거
}
