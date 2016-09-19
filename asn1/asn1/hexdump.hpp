#ifndef HAVE_HEXDUMP_T_HPP
#define HAVE_HEXDUMP_T_HPP

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <climits>
#include <memory>
#include <cctype>

class hexdump_t
{
	private:
	std::vector< uint8_t >	m_data;
	std::size_t				m_len;
	std::size_t				m_break;
	unsigned char			m_unprint;

	protected:
	template <typename ...Ts>
	static inline std::string
		fmt(const std::string fmt, Ts... var)
	{
		char 						b(0);
		ptrdiff_t					l(std::snprintf(&b, 0, fmt.c_str(), var...));
		ptrdiff_t					r(0);
		std::unique_ptr< char[] >	p(nullptr);

		if ( 0 == l )
			return std::string("");

		if ( 0 > l )
			throw std::runtime_error("hexdump_t::fmt(): Error encountered in std::snprintf(): '" + fmt + "' ret: " + std::to_string(l));


		if ( PTRDIFF_MAX == l )
			throw std::runtime_error("hexdump_t::fmt(): Overly large input encountered");

		l += 1;
		p.reset(new char[ l ]);

		r = std::snprintf(p.get(), l, fmt.c_str(), var...);

		if ( 0 > r )
			throw std::runtime_error("hexdump_t::fmt(): Error while formatting output");

		return std::string(p.get(), p.get() + r);
	}

	inline std::string get_line(std::size_t idx) const;

	public:
	hexdump_t(void);
	hexdump_t(const std::vector< uint8_t >&);
	hexdump_t(const std::string&);
	hexdump_t(const uint8_t*, const std::size_t);

	virtual ~hexdump_t(void);

	virtual void set(const std::vector< uint8_t >&);
	virtual void set(const std::string&);
	virtual void set(const uint8_t*, const std::size_t);

	virtual void append(const std::vector< uint8_t >&);
	virtual void append(const std::string&);
	virtual void append(const uint8_t*, const std::size_t);

	virtual void params(std::size_t len = 16, std::size_t brk = 8, unsigned char unprint = '.');

	virtual std::size_t line_length(void) { return m_len; }
	virtual std::size_t break_length(void) { return m_break; }
	virtual unsigned char unprintable_char(void) { return m_unprint; }

	virtual std::string to_string(void) const;
};

#endif