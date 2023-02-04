#include <Windows.h>
#include <string>
#include <fstream>
#include <vector>

bool ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer)
{
	std::ifstream file_ifstream(file_path, std::ios::binary);
	if (!file_ifstream)
		return false;

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();
	return true;
}

bool CreateFromMemory(const std::wstring& desired_file_path, const char* address, size_t size)
{
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);
	if (!file_ofstream.write(address, size))
	{
		file_ofstream.close();
		return false;
	}
	file_ofstream.close();
	return true;
}

int main()
{
	std::vector<uint8_t> Image = {};
	if (!ReadFileToMemory(L"Intel.dll", &Image))
		return 0;
	
	for (UINT32 i = 0; i < Image.size(); i++)
		Image[i] = (UINT8)(Image[i] ^ ((i + 7 * i + 8) + 4 + i));

	if (!CreateFromMemory(L"Intel.Xor", (char*)Image.data(), Image.size()))
		return 0;

	Image.clear();

	if (!ReadFileToMemory(L"Amd.dll", &Image))
		return 0;

	for (UINT32 i = 0; i < Image.size(); i++)
		Image[i] = (UINT8)(Image[i] ^ ((i + 7 * i + 8) + 4 + i));

	if (!CreateFromMemory(L"Amd.Xor", (char*)Image.data(), Image.size()))
		return 0;

	Image.clear();
	printf("sucess\n");
	return 0;
}
