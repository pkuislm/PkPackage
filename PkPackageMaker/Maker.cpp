// ConsoleLibPackage.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <fstream>
#include <cstdio>
#include <vector>
#include <Windows.h>
#include <locale>

#include "../cryptopp/cryptlib.h"
#ifdef _DEBUG
#pragma comment(lib, "cryptlib_d.lib")
#else
#pragma comment(lib, "cryptlib.lib")
#endif

#include "../cryptopp/camellia.h"
using CryptoPP::Camellia;

#include "../cryptopp/eax.h"
using CryptoPP::EAX;

#include "../cryptopp/zlib.h"
using CryptoPP::Inflator;
using CryptoPP::Deflator;

typedef unsigned char byte;
typedef unsigned int uint;

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

class Package_Writer
{
	std::ofstream m_stream;
	long long pos;
public:
	Package_Writer* operator<<(Package_Header* head)
	{
		this->m_stream.write(reinterpret_cast<const char*>(head), sizeof(Package_Header));
		return this;
	}

	Package_Writer* operator<<(Package_Entry* ent)
	{
		this->m_stream.write(reinterpret_cast<const char*>(ent), sizeof(Package_Entry)/* - sizeof(char*)*/);
		return this;
	}

	std::ofstream& GetStream()
	{
		return this->m_stream;
	}

	Package_Writer(const std::wstring& const outputPath)
	{
		m_stream = std::ofstream(outputPath, std::ios::binary);
		if (!m_stream.is_open())
		{
			throw("Cannot open output file.");
		}
		pos = 0;
	}

	~Package_Writer()
	{
		if (m_stream.is_open())
		{
			m_stream.flush();
			m_stream.close();
		}
	}
};

class Package_Reader
{
	std::ifstream m_stream;
	long long pos;
public:
	Package_Reader* operator>>(Package_Header* head)
	{
		//Package_Header hd(0);
		this->m_stream.read(reinterpret_cast<char*>(head), sizeof(Package_Header));
		return this;
	}

	Package_Reader* operator>>(Package_Entry* ent)
	{
		this->m_stream.read(reinterpret_cast<char*>(ent), sizeof(Package_Entry)/* - sizeof(char*)*/);
		//m_stream.write(ent.filename, ent.PathLen);
		return this;
	}

	std::ifstream& GetStream()
	{
		return this->m_stream;
	}

	Package_Reader(const std::string& const inputPath)
	{
		m_stream = std::ifstream(inputPath, std::ios::binary);
		if (!m_stream.is_open())
		{
			throw("Cannot open Package.");
		}
		pos = 0;
	}

	~Package_Reader()
	{
		if (m_stream.is_open())
		{
			//m_stream.flush();
			m_stream.close();
		}
	}
};

bool FinDAllFiles(wchar_t* lpPath, std::vector<std::wstring>& fileList)
{
	wchar_t szFind[MAX_PATH];
	WIN32_FIND_DATA FindFileData;

	wcscpy_s(szFind, lpPath);
	wcscat_s(szFind, L"\\*.*");

	HANDLE hFind = ::FindFirstFileW(szFind, &FindFileData);
	if (INVALID_HANDLE_VALUE == hFind)  return false;

	while (true)
	{
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (FindFileData.cFileName[0] != '.')
			{
				wchar_t szFile[MAX_PATH];
				wcscpy_s(szFile, lpPath);
				wcscat_s(szFile, L"\\");
				wcscat_s(szFile, (wchar_t*)(FindFileData.cFileName));
				FinDAllFiles(szFile, fileList);
			}
		}
		else
		{
			//std::cout << FindFileData.cFileName << std::endl;
			fileList.push_back(std::wstring(lpPath) + std::wstring(L"\\") + std::wstring(FindFileData.cFileName));
		}
		if (!FindNextFileW(hFind, &FindFileData))  break;
	}
	FindClose(hFind);
	return true;
}

#include <unordered_map>
std::unordered_map<std::string, Package_Entry> file_table;

int decompress() 
{
	std::string inpath("E:\\binout.pk");
	Package_Reader rd(inpath);
	Package_Header ph(0);
	rd >> &ph;
	if (ph.magic != 0x00504B50)
		throw"Unknown Magic";
	Package_Entry** pe = new Package_Entry * [ph.entrycount];
	for (int i = 0; i < ph.entrycount; ++i)
	{
		auto tpe = new Package_Entry();
		rd >> tpe;
		pe[i] = tpe;
	}

	for (int i = 0; i < ph.entrycount; ++i)
	{
		auto tpe = pe[i];
		byte* compressed = new byte[tpe->compressed_size];
		rd.GetStream().seekg(tpe->offset);
		rd.GetStream().read((char*)compressed, tpe->compressed_size);
		Inflator inf;
		inf.Put(compressed, tpe->compressed_size);
		inf.MessageEnd();
		long long avail = inf.MaxRetrievable();
		if (avail)
		{
			std::vector<byte> uncompressed;
			uncompressed.resize(avail);

			inf.Get(&uncompressed[0], uncompressed.size());
			//pkgw.GetStream().write((char*)uncompressed.data(), uncompressed.size());
		}
	}

	
	return 0;
}

bool CheckIfNeedCompress(std::wstring& file)
{
	if (file.find(L".otf") != std::wstring::npos || file.find(L".wmv") != std::wstring::npos)
	{
		return false;
	}
	return true;
}

void compress(std::wstring& inpath, std::wstring& outpath)
{
	std::vector<std::wstring> files;
	Package_Writer pkgw(outpath);


	FinDAllFiles((wchar_t*)inpath.c_str(), files);
	uint count = 0;
	Package_Header ph(files.size());
	Package_Entry** pe = new Package_Entry * [files.size() + 1];

	pkgw.GetStream().seekp(sizeof(Package_Header) + sizeof(Package_Entry) * files.size());
	for (auto i : files)
	{
		auto tpe = new Package_Entry();
		pe[count] = tpe;
		std::wstring pkg_file = i.substr(i.find_last_of(L'\\') + 1);
		transform(pkg_file.begin(), pkg_file.end(), pkg_file.begin(), ::tolower);
		//tpe->PathLen = pkg_file.size();
		//tpe->filename = new char[tpe->PathLen]{};
		wcscpy_s(tpe->filename, sizeof(Package_Entry::filename), pkg_file.c_str());
		count++;

		
		std::ifstream is(i, std::ios::binary);
		is.seekg(0, std::ios::end);
		tpe->size = is.tellg();
		is.seekg(0);
		char* uncomp = new char[tpe->size];
		is.read(uncomp, tpe->size);
		is.close();

		//Camellia::Encryption cae;

		if (CheckIfNeedCompress(pkg_file))
		{
			std::wcout << L"Compressing: " << i << '\n';
			Deflator deflator;
			deflator.Put((const byte*)uncomp, tpe->size);
			deflator.MessageEnd();

			delete[] uncomp;
			long long avail = deflator.MaxRetrievable();
			if (avail)
			{
				std::vector<byte> compressed;
				compressed.resize(avail);
				deflator.Get(&compressed[0], compressed.size());
				tpe->compressed_size = avail;
				tpe->offset = pkgw.GetStream().tellp();
				pkgw.GetStream().write((char*)compressed.data(), compressed.size());
			}
			else
			{
				throw "Compress error";
			}
		}
		else 
		{
			std::wcout << L"Adding: " << i << '\n';
			tpe->compressed_size = tpe->size;
			tpe->offset = pkgw.GetStream().tellp();
			pkgw.GetStream().write((char*)uncomp, tpe->size);
		}
		
	}

	pkgw.GetStream().seekp(sizeof(Package_Header));
	for (int i = 0; i < count; ++i)
	{
		auto tpe = pe[i];
		pkgw << tpe;
		//printf("%s\n", tpe->filename);
	}

	pkgw.GetStream().seekp(0);
	pkgw << &ph;
}

int wmain(int argc, wchar_t **argv)
{
	if ( argc != 3 )
	{
		std::wcout << L"Usage: [Folder to pack] [Output package path]\n";
		return 0;
	}
	setlocale(LC_ALL, "zh-CN");
	std::wstring inpath(argv[1]);
	std::wstring outpath(argv[2]);
	compress(inpath, outpath);
	std::wcout << L"Finished.\n";
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
