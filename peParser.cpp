#include <stdio.h>
#include <windows.h>
#include <iostream>
#include "RvaCounter.h"


//PE header 结构体
typedef struct PEHEADER
{
	unsigned int secCount;
	// unsigned int fileAlignment;
	unsigned int peHeaderBase;
	unsigned int optionalHeaderSize;
	unsigned char *dataDirectory;
}peHeader;

//函数声明
BOOL peCheck(FILE *peFile);
PEHEADER *peHeaderInfo(FILE *peFile);
void RE(int ret, int size);
void SE(int ret, int success);
BOOL sectionInfo(FILE *peFile, int off);
BOOL ImportTable(const unsigned char* dataDirectory, FILE *peFile);
BOOL getImportFuncInfo(FILE *peFile, unsigned int funcOffset);
BOOL getLibName(FILE*peFile, unsigned int nameRva);
long int RvaE(long int ret, int error);
BOOL getImportFuncTable(FILE *peFile, unsigned int funcOffset);

//临时变量。因为最初决定写这个程序的时候只是想简单的将PE header以及
//Section Table的解析结果输出,所以在最初的版本中我并没有使用结构体保
//存PE信息，而是直接使用buff临时性的保存数据并进行输出。现在程序渐渐
//地变得复杂，为了避免繁杂的重构我最终选择将先前的数据结构保留下来继
//续沿用，虽然这不是一个明智的选择，但并不妨功能的实现。
unsigned char *abyte = (unsigned char *)malloc (sizeof(unsigned char));
unsigned char *word = (unsigned char *)malloc (sizeof(unsigned char) * 2);
unsigned char *dword = (unsigned char *)malloc (sizeof(unsigned char) * 4);
unsigned char *byte8 = (unsigned char *)malloc (sizeof(unsigned char) * 8);
unsigned char *byte16 = (unsigned char *)malloc (sizeof(unsigned char) * 16);
unsigned char *byte128 = (unsigned char *)malloc (sizeof(unsigned char) * 128);

//RVAToOffset转换类
static RvaCounter *rvaCounter = new RvaCounter;

int main(int argc, char*argv[])
{
	int curSecAddr = 0;
	//用于保存PE header
	peHeader *header;
	printf(" \n");

	//输入参数检验
	if (argc != 2)
	{
		printf(" ERROR: Please Input A File \n");
		return (FALSE);
	}

	//打开文件
	FILE *peFile = fopen(argv[1], "rb"); 

	//检验文件是否为标准PE文件
	if (!peCheck(peFile))
		return (FALSE);

	//解析并获取PE Header
	if ((header = peHeaderInfo(peFile)) == NULL)
		return (FALSE);

	//回到Section Table基地址
	curSecAddr = header->peHeaderBase + header->optionalHeaderSize + 24;
	fseek(peFile, curSecAddr, SEEK_SET);

	//开始解析PE的Section Table
	printf(" Section Table Information:  \n");
	for (int i = 0; i < header->secCount; i++)
	{
		if (!sectionInfo(peFile, i))
			return (FALSE);
	}

	//回到Section Table基地址
	curSecAddr = header->peHeaderBase + header->optionalHeaderSize + 24;
	fseek(peFile, curSecAddr, SEEK_SET);

	//开始解析导入表
	printf(" Import Table Information:  \n");
	ImportTable(header->dataDirectory, peFile);

	//释放资源
	free(abyte);
	free(dword);
	free(word);
	free(byte8);
	free(byte16);
	free(byte128);
	delete header;
	return (TRUE);
}

BOOL peCheck(FILE *peFile)
{

	int ret = 0;
	RE(fread(word, 2, 1, peFile), 1);

	//检验MZ双字标志
	if (*(unsigned short int *)word != 0x5a4d)
	{
		printf(TEXT(" This file is not a vaild PE. \n"));
		return (FALSE);
	}

	//跳转至PE header
	SE(fseek(peFile, 0x3cL, SEEK_SET), 0);
	RE(fread(word, 2, 1, peFile), 1);
	SE(fseek(peFile, *(unsigned short int *)word, SEEK_SET), 0);
	RE(fread(word, 2, 1, peFile), 1);

	//检验PE双字标志
	if (*(unsigned short int *)word == 0x4550)
	{
		printf(TEXT(" This file is a vaild PE. \n\n"));
		SE(fseek(peFile, -2, SEEK_CUR), 0);				//回到PE header基地址
		return (TRUE);
	}
	SE(fseek(peFile, -2, SEEK_CUR), 0);					//回到PE header基地址
	return (FALSE);
}


/*
typedef struct _IMAGE_OPTIONAL_HEADER
{
//
// Standard fields.
//
	+18h WORD Magic; // 标志字, ROM 映像（0107h）,普通可执行文件（010Bh）
	+1Ah BYTE MajorLinkerVersion; // 链接程序的主版本号
	+1Bh BYTE MinorLinkerVersion; // 链接程序的次版本号
	+1Ch DWORD SizeOfCode; // 所有含代码的节的总大小
	+20h DWORD SizeOfInitializedData; // 所有含已初始化数据的节的总大小
	+24h DWORD SizeOfUninitializedData; // 所有含未初始化数据的节的大小
	+28h DWORD AddressOfEntryPoint; // 程序执行入口RVA
	+2Ch DWORD BaseOfCode; // 代码的区块的起始RVA
	+30h DWORD BaseOfData; // 数据的区块的起始RVA
//
// NT additional fields. 以下是属于NT结构增加的领域。
//
	+34h DWORD ImageBase; // 程序的首选装载地址
	+38h DWORD SectionAlignment; // 内存中的区块的对齐大小
	+3Ch DWORD FileAlignment; // 文件中的区块的对齐大小
	+40h WORD MajorOperatingSystemVersion; // 要求操作系统最低版本号的主版本号
	+42h WORD MinorOperatingSystemVersion; // 要求操作系统最低版本号的副版本号
	+44h WORD MajorImageVersion; // 可运行于操作系统的主版本号
	+46h WORD MinorImageVersion; // 可运行于操作系统的次版本号
	+48h WORD MajorSubsystemVersion; // 要求最低子系统版本的主版本号
	+4Ah WORD MinorSubsystemVersion; // 要求最低子系统版本的次版本号
	+4Ch DWORD Win32VersionValue; // 莫须有字段，不被病毒利用的话一般为0
	+50h DWORD SizeOfImage; // 映像装入内存后的总尺寸
	+54h DWORD SizeOfHeaders; // 所有头 + 区块表的尺寸大小
	+58h DWORD CheckSum; // 映像的校检和
	+5Ch WORD Subsystem; // 可执行文件期望的子系统
	+5Eh WORD DllCharacteristics; // DllMain()函数何时被调用，默认为 0
	+60h DWORD SizeOfStackReserve; // 初始化时的栈大小
	+64h DWORD SizeOfStackCommit; // 初始化时实际提交的栈大小
	+68h DWORD SizeOfHeapReserve; // 初始化时保留的堆大小
	+6Ch DWORD SizeOfHeapCommit; // 初始化时实际提交的堆大小
	+70h DWORD LoaderFlags; // 与调试有关，默认为 0
	+74h DWORD NumberOfRvaAndSizes; // 下边数据目录的项数，这个字段自Windows NT 发布以来 // 一直是16
	+78h IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
// 数据目录表
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
	 */
PEHEADER *peHeaderInfo(FILE *peFile)
{
	//实例化结构体，用于保存并返回PE header 结构
	peHeader *header = new PEHEADER;

	//记录PE header基地址
	header->peHeaderBase = ftell(peFile);
	printf(" PE Header Information:  \n");
	int ret = 0;
	//跳过PE检验
	SE(fseek(peFile, 4, SEEK_CUR), 0);

	//开始解析
	RE(fread(word, 2, 1, peFile), 1);
	printf("\t Machine: 0x%x \n", *(unsigned short int *)word);
	RE(fread(word, 2, 1, peFile), 1);
	printf("\t Number Of Section: %d \n", *(unsigned short int *)word);
	header->secCount = *(unsigned short int *)word;
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t File Creation Date Time: %d \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Address Of Symbol Table: 0x%x \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Number Of Symbol Table: %d \n", *(unsigned int *)dword);
	RE(fread(word, 2, 1, peFile), 1);
	printf("\t Size Of Optional Header: %d \n", *(unsigned short int *)word);
	header->optionalHeaderSize = *(unsigned short int *)word;
	RE(fread(word, 2, 1, peFile), 1);
	printf("\t File Type: 0x%x \n", *(unsigned short int *)word);
	printf("\n");

	//optional header 可选头解析开始
	RE(fread(word, 2, 1, peFile), 1);
	printf("\t Optional Header Magic: 0x%x \n", *(unsigned short int *)word);
	RE(fread(abyte, 1, 1, peFile), 1);
	printf("\t Major Linker Version: 0x%x \n", *(BYTE *)abyte);
	RE(fread(abyte, 1, 1, peFile), 1);
	printf("\t Minor Linker Version: 0x%x \n", *(BYTE *)abyte);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Size Of Code: %d \n", *(unsigned int *)dword);
	SE(fseek(peFile, 0x8, SEEK_CUR), 0);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Address Of Entry Point: 0x%x \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Base Of Code: 0x%x \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Base Of Data: 0x%x \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Priority Loading Address: 0x%x \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Section Alignment: 0x%x \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t File alignment: 0x%x \n", *(unsigned int *)dword);
	RE(fread(word, 2, 1, peFile), 1);
	printf("\t Major Subsystem Version: %d \n", *(unsigned short int *)word);
	RE(fread(word, 2, 1, peFile), 1);
	printf("\t Minor Subsystem Version: %d \n", *(unsigned short int *)word);
	SE(fseek(peFile, header->peHeaderBase + 0x78, SEEK_SET), 0);

	//获取data directory，用于之后的import table信息获取
	RE(fread(byte128, 128, 1, peFile), 1);
	header->dataDirectory = byte128;

	printf(" \n");
	return header;
}



/*
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
 */
BOOL sectionInfo(FILE *peFile, int off)
{
	//用于记录Section N基地址
	unsigned int sectionNBase = 0;

	//记录Section Table基地址
	unsigned int baseOffset = ftell(peFile);

	//用于记录Section Name
	char *secName = (char *)malloc(sizeof(char) * 9);

	//用于记录Section N 虚拟偏移地址，用于过后虚拟偏移地址解析成文件偏移
	int baseRva = 0;

	//用于记录Section大小
	int size = 0;
	RE(fread(byte8, 8, 1, peFile), 1);
	memcpy(secName, byte8, 8);
	secName[8] = '\0';
	printf("\t Section Name: %s \n", secName);
	SE(fseek(peFile, 4, SEEK_CUR), 0);
	RE(fread(dword, 4, 1, peFile), 1);
	baseRva = *(unsigned int *)dword;
	printf("\t Virtual Address: 0x%x \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	size = *(unsigned int *)dword;
	printf("\t Size Of Raw Data: 0x%x \n", *(unsigned int *)dword);
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Pointer To Raw Data: 0x%x \n", *(unsigned int *)dword);
	sectionNBase = *(unsigned int *)dword;
	RE(fread(dword, 4, 1, peFile), 1);
	printf("\t Characteristics: 0x%x \n", *(unsigned int *)dword);
	printf("\n");
	SE(fseek(peFile, baseOffset + 40, SEEK_SET), 0);
	rvaCounter->addSection(baseRva, size, sectionNBase);
	free(secName);
	return (TRUE);
}


BOOL ImportTable(const unsigned char* dataDirectory, FILE *peFile)
{
	unsigned int curOffset = 0;
	long int offset = 0;

	//用于记录import symbols信息
	unsigned char *importSymbolsAddr = (unsigned char *)malloc(sizeof(unsigned char) * 4);
	unsigned char *importSymbolsSize = (unsigned char *)malloc(sizeof(unsigned char) * 4);

	//import_desc
	unsigned char *funcTableRva = (unsigned char *)malloc(sizeof(unsigned char) * 4);
	unsigned char *nameRva = (unsigned char *)malloc(sizeof(unsigned char) * 4);
	unsigned char *firstThunkRva = (unsigned char *)malloc(sizeof(unsigned char) * 4);

	//直接获取虚拟偏移和大小
	memcpy(importSymbolsAddr, dataDirectory + 8 * 1, 4);
	memcpy(importSymbolsSize, dataDirectory + 8 * 1 + 4, 4);

	//虚拟偏移转文件偏移
	offset = RvaE(rvaCounter->RvaToOffset(*(unsigned int *)importSymbolsAddr), -1);
	if (offset == 0)
	{
		free(importSymbolsAddr);
		free(importSymbolsSize);
		free(funcTableRva);
		free(nameRva);
		free(firstThunkRva);
		return (FALSE);
	}

	//跳转至引入表 image import descriptor
	SE(fseek(peFile, offset, SEEK_SET), 0);	
	curOffset = ftell(peFile);

	//遍历image import descriptor
	while(1)
	{
		
		//这个结构体数组由全0成员作为结尾，此处通过判断全0来判断是否结尾
		int allZero = 1;
		for(int i = 0; i < 20; i++)
		{
			RE(fread(abyte, 1, 1, peFile), 1);
			if (*abyte != 0)
				allZero = 0;
		}
		if (allZero == 1)
			break;

		//获取数据
		SE(fseek(peFile, curOffset, SEEK_SET), 0);
		RE(fread(funcTableRva, 4, 1, peFile), 1);
		SE(fseek(peFile, 8, SEEK_CUR), 0);
		RE(fread(nameRva, 4, 1, peFile), 1);
		RE(fread(firstThunkRva, 4, 1, peFile), 1);

		//Library Name地址转换
		long int nameOffset = RvaE(rvaCounter->RvaToOffset(*(unsigned int *)nameRva), -1);
		if (nameOffset == 0)
		{
			curOffset = ftell(peFile);
			continue;
		}
		//获取Library Name
		getLibName(peFile, (unsigned int)nameOffset);

		//函数导入表地址转换
		offset = RvaE(rvaCounter->RvaToOffset(*(unsigned int *)funcTableRva), -1);
		if (offset == 0)
		{
			curOffset = ftell(peFile);
			continue;
		}

		//回到当前遍历的descriptor成员的地址
		curOffset = ftell(peFile);

		//获取函数导入表信息
		getImportFuncTable(peFile, (unsigned int)offset);
	}

	//释放内存
	free(importSymbolsAddr);
	free(importSymbolsSize);
	free(funcTableRva);
	free(nameRva);
	free(firstThunkRva);
	return (TRUE);
}


//获取函数导入表信息
BOOL getImportFuncTable(FILE *peFile, unsigned int funcOffset)
{
	long int nameOffset = 0;
	unsigned char *nameRva = (unsigned char *)malloc(sizeof(nameRva) * 4);

	//记录基地址
	unsigned int baseOffset = ftell(peFile);

	//跳转至函数导入表
	SE(fseek(peFile, funcOffset, SEEK_SET), 0);
	while(1)
	{
		//获取函数名地址
		RE(fread(nameRva, 4, 1, peFile), 1);
		nameOffset = RvaE(rvaCounter->RvaToOffset(*(unsigned int *)nameRva), -1);
		//全零即结尾，跳出循环
		if(nameOffset == 0)
		{
			free(nameRva);
			break;
		}
		//通过函数名地址获取函数信息（函数索引和函数名）
		getImportFuncInfo(peFile, nameOffset);
	}

	//回到基地址
	SE(fseek(peFile, baseOffset, SEEK_SET), 0);
	free(nameRva);
	return (TRUE);
}


//获取函数信息
BOOL getImportFuncInfo(FILE *peFile, unsigned int funcOffset)
{
	char *name;
	int nameLen = 0;

	//记录基地址
	unsigned int baseOffset = ftell(peFile);

	//跳转至函数名，前面有两字节索引，因此+2
	SE(fseek(peFile, funcOffset + 2, SEEK_SET), 0);

	//计算函数名大小
	do {
		nameLen++;
		RE(fread(abyte, 1, 1, peFile), 1);
	} while (*abyte != 0x00);
	SE(fseek(peFile, -nameLen, SEEK_CUR), 0);

	//保存函数名并输出
	name = (char *)malloc(sizeof(char)*nameLen);
	RE(fread(name, nameLen, 1, peFile), 1);
	printf("\t Function Name: %s \n", name);

	//回到基地址
	SE(fseek(peFile, baseOffset, SEEK_SET), 0);

	//释放
	free(name);
	return (TRUE);
}


//获取库名
BOOL getLibName(FILE*peFile, unsigned int nameOffset)
{
	//记录基地址
	unsigned int baseOffset = ftell(peFile);
	char *name;
	unsigned int nameLen = 0;
	SE(fseek(peFile, nameOffset, SEEK_SET), 0);

	//计算库名大小
	do {
		nameLen++;
		RE(fread(abyte, 1, 1, peFile), 1);
	} while (*abyte != 0x00);
	SE(fseek(peFile, -nameLen, SEEK_CUR), 0);

	//保存库名并输出
	name = (char *)malloc(sizeof(char)*nameLen);
	RE(fread(name, nameLen, 1, peFile), 1);
	printf("\n\t Library Name: %s \n", name);

	//回到基地址
	SE(fseek(peFile, baseOffset, SEEK_SET), 0);
	free(name);
	return (TRUE);
}


/***************************************************************/
//错误统一处理函数
void RE(int ret, int size)
{
	if (ret != size)
	{
		printf(TEXT(" ERROR: Read File Failed \n"));
		exit (FALSE);
	}
}

void SE(int ret, int success)
{
	if (ret != success)
	{
		printf(TEXT(" This file is a vaild PE. \n"));
		exit (TRUE);
	}
}

long int RvaE(long int ret, int error)
{
	if (ret == error)
	{
		printf(" ERROR: File Offset is Beyond The Limit");
	}
	return ret;
}
/***************************************************************/