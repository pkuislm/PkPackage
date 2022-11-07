#pragma once
typedef unsigned char byte;
typedef unsigned int uint;
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <Windows.h>

#pragma pack(push)
#pragma pack(1)
struct Package_Entry
{
	uint offset = 0;
	uint size = 0;
	uint compressed_size = 0;
	uint xorkey = 0;
	byte key[16]{};
	byte iv[16]{};
	wchar_t filename[64]{};
};

struct Package_Header
{
	int magic = 0x00504B50;
	int version = 0;
	int entrycount;
	Package_Header(int ec) :entrycount(ec) {};
};
#pragma pack(pop)

struct FileTable
{
	std::wstring pkg_path;
	std::unordered_map<std::wstring, Package_Entry*> m_table;
};
std::vector<FileTable> file_tables;

bool TryOpenPkgFile(std::wstring& filename, byte* buffer, int*size);
bool SetUpFileTable(std::wstring package, bool echo = false, bool append = true);