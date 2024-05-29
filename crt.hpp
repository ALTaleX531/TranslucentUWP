#pragma once
// C
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cfloat>
#include <climits>
#include <clocale>
#include <cmath>
#include <csetjmp>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
// C (C++ 11)
#include <cfenv>
#include <cinttypes>
#include <cstdint>
#include <cuchar>
#include <cwchar>
#include <cwctype>
// C++
#include <algorithm>
#include <bitset>
#include <complex>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <ios>
#include <iosfwd>
#include <iostream>
#include <istream>
#include <iterator>
#include <limits>
#include <list>
#include <locale>
#include <map>
#include <memory>
#include <new>
#include <numeric>
#include <ostream>
#include <queue>
#include <set>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <typeinfo>
#include <utility>
#include <valarray>
#include <vector>
// C++ 11
#include <array>
#include <atomic>
#include <chrono>
#include <codecvt>
#include <condition_variable>
#include <forward_list>
#include <future>
#include <initializer_list>
#include <mutex>
#include <random>
#include <ratio>
#include <regex>
#include <scoped_allocator>
#include <system_error>
#include <thread>
#include <tuple>
#include <typeindex>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
// C++ 14
#include <shared_mutex>
// C++ 17
#include <any>
#include <charconv>
#include <cuchar>
#include <execution>
#include <filesystem>
#include <memory_resource>
#include <optional>
#include <string_view>
#include <tuple>
#include <variant>
// C++ 20
#include <bit>
#include <concepts>
#include <compare>
#include <coroutine>
#include <format>
#include <latch>
#include <ranges>
#include <version>
#include <semaphore>
#include <span>
#include <syncstream>

namespace std
{
	template <typename TLambda>
	class lambda_call
	{
	public:
		lambda_call(const lambda_call&) = delete;
		lambda_call& operator=(const lambda_call&) = delete;
		lambda_call& operator=(lambda_call&& other) = delete;

		inline explicit lambda_call(TLambda&& lambda) noexcept : m_lambda(std::move(lambda))
		{
			static_assert(std::is_same<decltype(lambda()), void>::value, "scope_exit lambdas must not have a return value");
			static_assert(!std::is_lvalue_reference<TLambda>::value && !std::is_rvalue_reference<TLambda>::value, "scope_exit should only be directly used with a lambda");
		}
		inline lambda_call(lambda_call&& other) noexcept : m_lambda(std::move(other.m_lambda)), m_call(other.m_call)
		{
			other.m_call = false;
		}
		inline ~lambda_call() noexcept
		{
			reset();
		}
		inline void release() noexcept
		{
			m_call = false;
		}
		inline void reset() noexcept
		{
			if (m_call)
			{
				m_call = false;
				m_lambda();
			}
		}
		[[nodiscard]] inline explicit operator bool() const noexcept
		{
			return m_call;
		}
	protected:
		TLambda m_lambda;
		bool m_call = true;
	};

	template <typename TLambda>
	[[nodiscard]] inline auto scope_exit(TLambda&& lambda) noexcept
	{
		return lambda_call<TLambda>(std::forward<TLambda>(lambda));
	}
}