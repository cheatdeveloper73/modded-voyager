#pragma once
#include <immintrin.h>
#pragma warning(disable : 4172)

namespace CryImplement
{
    #define COM_RANDOMIZE_INTERNAL_PRIME_LOW 16807

    #define COM_RANDOMIZE_INTERNAL_MAX_32 0xFFFFFFFF
    #define COM_RANDOMIZE_INTERNAL_MAX_64 0xFFFFFFFFFFFFFFFF

    #define COM_RANDOMIZE_INTERNAL_SEED 4919
    #define COM_RANDOMIZE_INTERNAL_VALUE_IN_BOUNDS(value) (sizeof (value) == sizeof (char) ? (value < 256 && value > -126) : (sizeof (value)) == sizeof (short) ? (value < 65535 && value > -32767) : (sizeof (value) == sizeof (int)) ? (value < 4294967295 && value > -2147483647) : (sizeof (value) == sizeof (long long) ? (value < 9223372036854775807 && value > -9223372036854775807) : 0))
    #define COM_RANDOMIZE_INTERNAL_SEED_COMPILE ((((((__LINE__ * __LINE__)))) + ((__TIME__ [0] + __TIME__ [1] + __TIME__ [2] + __TIME__ [3] + __TIME__ [4]) ^ (__TIME__ [5] + __TIME__ [6] + __TIME__ [7]))))
    #define COM_RANDOMIZE_GENERATE_UNSAFE_SEED(seed, value) ((COM_RANDOMIZE_INTERNAL_SEED_COMPILE ^ value) * seed)
    #define COM_RANDOMIZE_GENERATE_SAFE_SEED(seed, value) (COM_RANDOMIZE_INTERNAL_VALUE_IN_BOUNDS (COM_RANDOMIZE_GENERATE_UNSAFE_SEED (seed, value)) ? COM_RANDOMIZE_GENERATE_UNSAFE_SEED (seed, value) : ((COM_RANDOMIZE_GENERATE_UNSAFE_SEED (seed, value) - COM_RANDOMIZE_INTERNAL_MAX_32) / 8) ^ seed)
    #define COM_RANDOMIZE_GENERATE(value) COM_RANDOMIZE_GENERATE_SAFE_SEED (value, (__COUNTER__ * __COUNTER__))

	class XorString 
	{
	public:
		template <unsigned int size>
		struct StringBytesContainer 
		{
			static const unsigned int m_blocksCount = size >= 8 ? ((size / 16) + (size % 16 != 0)) * 2 : 1;
			__m128i m_blocks [m_blocksCount];
			__m128i m_keys   [m_blocksCount];
		};

		struct StringHolder 
		{
			const char* const m_ascii;
			const wchar_t* const m_wide;
			unsigned long long m_seed;

			template <unsigned int length>
			constexpr StringHolder(const char (&source) [length], unsigned long long seed) : m_ascii (source), m_seed (seed), m_wide (L"\0") {};

			template <unsigned int length>
			constexpr StringHolder(const wchar_t (&source) [length], unsigned long long seed) : m_wide (source), m_seed (seed), m_ascii ("\0") {};
		};

		template <unsigned int size>
		struct StringConversionPrimitive 
		{
			__m128i m_buffer[size];
		};

		template <unsigned int length>
		static constexpr __forceinline auto GenerateBlock(const wchar_t stream [length], unsigned long long seed) 
		{
			unsigned char buffer [length] = {};
			unsigned int safeBytesIterator = 0;

			for (unsigned int byteIterator = 0; byteIterator < length; byteIterator += 2) 
			{
				wchar_t temp = stream[safeBytesIterator];
				buffer[byteIterator] = temp & 0xFF;
				buffer[byteIterator + 1] = temp >> 8;
				safeBytesIterator++;
			}
			buffer [length - 2] = '\0';
			buffer [length - 1] = '\0';
			return GenerateBlock <length> (buffer, seed);
		}

		template <unsigned int length>
		static constexpr __forceinline auto GenerateBlock(const char stream [length], unsigned long long seed) 
		{
			unsigned char buffer [length] = {};
			for (unsigned int byteIterator = 0; byteIterator < length; byteIterator++) 
			{
				buffer [byteIterator] = stream [byteIterator];
            }
            return GenerateBlock<length> (buffer, seed);
		}
		template <unsigned int length>
		static constexpr __forceinline auto GenerateBlock(const unsigned char stream [length], unsigned long long seed) 
		{
			StringBytesContainer <length> container {};
			unsigned int blazeBlocksIterator = 0;

			for (unsigned int blocksIterator = 0; blocksIterator < container.m_blocksCount; blocksIterator++) 
			{
				__m128i buffer = {}, key = {};
				char byteStreamChildId = 0;

				for (char byteStreamIterator = 0; byteStreamIterator < 2; byteStreamIterator++) 
				{
					unsigned long long bufferStream = 0;
					for (unsigned short byteIterator = 0; byteIterator < 8; byteIterator++) 
					{
						bufferStream = bufferStream | (static_cast <unsigned long long> (((byteIterator + (8 * (blocksIterator + byteStreamIterator))) < length ? ((stream [byteIterator + (8 * (blocksIterator + byteStreamIterator))]) << (((blocksIterator + byteStreamIterator) % 1) * 32)) : 0)) << (8 * byteIterator));
					}
					buffer.m128i_u64[byteStreamChildId] = bufferStream;
					byteStreamChildId++;
				}
				blocksIterator++;
				key.m128i_u64 [0] = COM_RANDOMIZE_GENERATE_SAFE_SEED(buffer.m128i_u64 [0], seed);
				key.m128i_u64 [1] = COM_RANDOMIZE_GENERATE_SAFE_SEED(buffer.m128i_u64 [0] - seed, buffer.m128i_u64 [0] + seed);
				container.m_blocks[blazeBlocksIterator].m128i_u64 [0] = buffer.m128i_u64 [0] ^ key.m128i_u64 [0];
				container.m_blocks[blazeBlocksIterator].m128i_u64 [1] = buffer.m128i_u64 [1] ^ key.m128i_u64 [1];
				container.m_keys[blazeBlocksIterator].m128i_u64 [0] = key.m128i_u64 [0];
				container.m_keys[blazeBlocksIterator].m128i_u64 [1] = key.m128i_u64 [1];
				blazeBlocksIterator++;
			}
			return container;
		}

		template <unsigned int size>
		static __forceinline auto DecryptBlock(const StringBytesContainer <size> container) 
		{
			StringConversionPrimitive<size> primitives;
			for (unsigned int blocksIterator = 0; blocksIterator < container.m_blocksCount; blocksIterator++) 
			{
				primitives.m_buffer[blocksIterator].m128i_u64 [0] = 0;
				primitives.m_buffer[blocksIterator].m128i_u64 [1] = 0;
			}
			for (unsigned int blocksIterator = 0; blocksIterator < container.m_blocksCount; blocksIterator++) 
			{
				primitives.m_buffer[blocksIterator] = _mm_xor_si128 (container.m_blocks [blocksIterator], container.m_keys [blocksIterator]);
			}
			return primitives;

		}
		template <unsigned int length, StringHolder holder>
		static __forceinline auto DecryptAsciiBlock()
		{
			constexpr auto data = CryImplement::XorString::GenerateBlock <length> (holder.m_ascii, holder.m_seed);
			return (const char*)DecryptBlock(data).m_buffer;
		}

		template <unsigned int length, StringHolder holder>
		static __forceinline auto DecryptWideBlock()
		{
			constexpr auto data = CryImplement::XorString::GenerateBlock <length> (holder.m_wide, holder.m_seed);
			return (const wchar_t*)DecryptBlock (data).m_buffer;
		}
	};

	#define CRY_XORSTR_LIGHT(string) CryImplement::XorString::DecryptAsciiBlock<sizeof (string), CryImplement::XorString::StringHolder { string, __COUNTER__ * __LINE__ }> ()
	#define CRY_XORSTR_LIGHT_W(string) CryImplement::XorString::DecryptWideBlock<sizeof (string), CryImplement::XorString::StringHolder { string, __COUNTER__ * __LINE__ }> ()

}