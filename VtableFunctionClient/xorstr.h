#pragma once
#include <string>
#include <array>
#include <cstdarg>
#include <utility>

namespace XorCompileTime
{
	constexpr auto time = __TIME__;
	constexpr auto seed = static_cast<int>(time[7]) + static_cast<int>(time[6]) * 10 + static_cast<int>(time[4]) * 60 + static_cast<int>(time[3]) * 600 + static_cast<int>(time[1]) * 3600 + static_cast<int>(time[0]) * 36000;

	template < int iValue >
	struct RandomGenerator
	{
	private:
		static constexpr unsigned a = 16807;
		static constexpr unsigned m = 0x7FFFFFFF;
		static constexpr unsigned s = RandomGenerator<iValue - 1>::value;
		static constexpr unsigned lo = a * (s & 0xFFFF);
		static constexpr unsigned hi = a * (s >> 16);
		static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16);
		static constexpr unsigned hi2 = hi >> 15;
		static constexpr unsigned lo3 = lo2 + hi;
	public:
		static constexpr unsigned max = m;
		static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
	};

	template <>
	struct RandomGenerator<0>
	{
		static constexpr unsigned value = seed;
	};

	template < int N, int M >
	struct RandomInt
	{
		static constexpr auto value = RandomGenerator< N + 1 >::value % M;
	};

	template < int N >
	struct RandomChar
	{
		static const char value = static_cast<char>(1 + RandomInt< N, 0x7F - 1 >::value);
	};

	template < int N >
	struct RandomCharW
	{
		static const wchar_t value = static_cast<wchar_t>(1 + RandomInt< N, 0x7F - 1 >::value);
	};

	template <size_t N, int K>
	struct XorString
	{
	private:
		const char _key;
		std::array< char, N + 1 > _encrypted;
		constexpr char enc(char c) const { return c ^ _key; }
		char dec(char c) const { return c ^ _key; }
	public:
		template <size_t... Is>
		constexpr __forceinline XorString(const char* str, std::index_sequence< Is... >) : _key(RandomChar< K >::value), _encrypted{ enc(str[Is])... } {}

		__forceinline decltype(auto) decrypt(void)
		{
			for (size_t i = 0; i < N; ++i)
			{
				_encrypted[i] = dec(_encrypted[i]);
			}
			_encrypted[N] = '\0';
			return _encrypted.data();
		}
	};

	template <size_t N, int K>
	struct XorStringW
	{
	private:
		const wchar_t _key;
		std::array< wchar_t, N + 1 > _encrypted;
		constexpr wchar_t enc(wchar_t c) const { return c ^ _key; }
		wchar_t dec(wchar_t c) const { return c ^ _key; }
	public:
		template <size_t... Is>
		constexpr __forceinline XorStringW(const wchar_t* str, std::index_sequence< Is... >) : _key(RandomCharW< K >::value), _encrypted{ enc(str[Is])... } {}

		__forceinline decltype(auto) decrypt(void)
		{
			for (size_t i = 0; i < N; ++i)
			{
				_encrypted[i] = dec(_encrypted[i]);
			}
			_encrypted[N] = '\0';
			return _encrypted.data();
		}
	};


#define XorString(s) (XorCompileTime::XorString<sizeof( s ) - 1,__COUNTER__>(s, std::make_index_sequence<sizeof(s) - 1>()).decrypt())
#define XorStringW(s) (XorCompileTime::XorStringW<sizeof( s ) - 1,__COUNTER__>(s, std::make_index_sequence<sizeof(s) - 1>()).decrypt())
}


