// LibPackage.cpp : 定义静态库的函数。
//
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容

#include "Lib.h"
#include <cstdio>
#include <vector>
#include <Windows.h>

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

class Package_Reader
{
	std::ifstream m_stream;
	bool is_open;
	//long long pos;
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

	bool IsOpen()
	{
		return is_open;
	}

	Package_Reader(const std::wstring& inputPath):is_open(true)
	{
		m_stream = std::ifstream(inputPath, std::ios::binary);
		if (!m_stream.is_open())
		{
			is_open = false;
			//throw("Cannot open Package.");
		}
		//pos = 0;
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

bool SetUpFileTable(std::wstring&& package, bool echo, bool append)
{
	if (!append) file_tables.clear();
	FileTable ft;
	ft.pkg_path = std::move(package);
	Package_Reader rd(ft.pkg_path);
	if (rd.IsOpen())
	{
		Package_Header ph(0);
		rd >> &ph;
		if (ph.magic != 0x00504B50)
			throw"Unknown Magic";
		for (int i = 0; i < ph.entrycount; ++i)
		{
			auto tpe = new Package_Entry();
			rd >> tpe;
			if (echo) std::wcout << L"[PackageLoader] " << tpe->filename << '\n';
			ft.m_table.emplace(std::make_pair(std::wstring(tpe->filename), tpe));
		}
		file_tables.emplace_back(ft);
		return true;
	}
	return false;
}

bool UpdateFileTable(std::wstring&& OrigName, std::wstring&& package, bool echo)
{
	try
	{
		for (auto it = file_tables.begin(); it != file_tables.end(); ++it)
		{
			if (it->pkg_path == OrigName)
			{
				//这里是直接找到需要覆盖的封包，然后在他前面插入新的封包，这样可以实现文件覆盖
				//不过实际上完全可以直接在封包表最后端添加，只需把查找顺序改为逆序
				//但已经懒得改了，就这样吧
				FileTable ft;
				ft.pkg_path = std::move(package);
				Package_Reader rd(ft.pkg_path);
				if (rd.isOpen())
				{
					Package_Header ph(0);
					rd >> &ph;
					if (ph.magic != 0x00504B50)
						throw"Unknown Magic";
					for (int i = 0; i < ph.entrycount; ++i)
					{
						auto tpe = new Package_Entry();
						rd >> tpe;
						if (echo) std::wcout << L"[PackageUpdate] " << tpe->filename << '\n';
						ft.m_table.emplace(std::make_pair(std::wstring(tpe->filename), tpe));
					}
					file_tables.insert(it, ft);
					return true;
				}
				return false;
			}
		}
	}
	catch (std::exception e)
	{
		//MessageBoxA(NULL,  e.what(), "PackageReadError", MB_OK | MB_ICONERROR);
		//std::cout << "[PackageUpdate] " << e.what() << " in UpdatePkgFile.\n";
		return false;
	}
}

bool TryOpenPkgFile(const std::wstring& filename, byte* buffer, int* size)
{
	try
	{
		for (auto i : file_tables)
		{
			auto it = i.m_table.find(filename);
			if (it != i.m_table.end())
			{
				auto tpe = it->second;
				//TryOpenPackageFile
				//为啥要返回一个最大值呢，因为如果多次进行分配，似乎会出现bad allocation的异常
				//我也不知道咋回事，烦死了（
				if (!buffer)
				{
					*size = tpe->size > tpe->compressed_size ? tpe->size : tpe->compressed_size;
					return true;
				}

				std::ifstream fin(i.pkg_path, std::ios::binary);
				if (fin.is_open())
				{
					fin.seekg(tpe->offset);
					//auto tmp = new byte[tpe->compressed_size];
					fin.read((char*)buffer, tpe->compressed_size);
					fin.close();

					if (tpe->size != tpe->compressed_size)
					{
						Inflator* inf = new Inflator();
						inf->Put(buffer, tpe->compressed_size);
						inf->MessageEnd();
						//delete[] tmp;
						long long avail = inf->MaxRetrievable();
						if (avail)
						{
							inf->Get(buffer, avail);
							delete inf;
							//inf.IsolatedFlush(false,true);
							*size = avail;
							return true;
						}
					}
					else 
					{
						*size = tpe->size;
						return true;
					}
				}
				else
				{
					return false;
				}
			}
		}
	}
	catch (std::exception e)
	{
		//MessageBoxA(NULL,  e.what(), "PackageReadError", MB_OK | MB_ICONERROR);
		std::cout << "[Package] " << e.what() << " in TryOpenPkgFile.\n";
		return false;
	}

	return false;
}
