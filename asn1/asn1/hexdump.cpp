#include "hexdump.hpp"

hexdump_t::hexdump_t(void) : m_len(16), m_break(8), m_unprint('.')
{
	return;
}

hexdump_t::hexdump_t(const std::vector< uint8_t >& vec) : m_len(16), m_break(8), m_unprint('.')
{
	set(vec);
	return;
}

hexdump_t::hexdump_t(const std::string& str) : m_len(16), m_break(8), m_unprint('.')
{
	set(str);
	return;
}

hexdump_t::hexdump_t(const uint8_t* ptr, const std::size_t siz) : m_len(16), m_break(8), m_unprint('.')
{
	set(ptr, siz);
}

hexdump_t::~hexdump_t(void)
{
	m_data.clear();
	return;
}

void
hexdump_t::set(const std::vector< uint8_t >& vec)
{
	m_data = vec;
	return;
}

void
hexdump_t::set(const std::string& str)
{
	m_data.clear();

	if ( 0 != str.length() )
		append(str);

	return;
}

void
hexdump_t::set(const uint8_t* ptr, const std::size_t siz)
{
	m_data.clear();

	if ( 0 != siz )
		append(ptr, siz);

	return;
}

void
hexdump_t::append(const std::vector< uint8_t >& vec)
{
	m_data.insert(m_data.end(), vec.begin(), vec.end());
	return;
}

void
hexdump_t::append(const std::string& str)
{
	for ( std::size_t idx = 0; idx < str.length(); idx++ )
		m_data.push_back(str[ idx ]);

	return;
}

void
hexdump_t::append(const uint8_t* ptr, const std::size_t siz)
{
	if ( nullptr == ptr || 0 == siz )
		throw std::runtime_error("hexdump_t::append(): Invalid parameter(s)");

	for ( std::size_t idx = 0; idx < siz; idx++ )
		m_data.push_back(ptr[ idx ]);

	return;
}

void
hexdump_t::params(std::size_t len, std::size_t brk, unsigned char unp)
{
	m_len = len;
	m_break = brk;
	m_unprint = unp;

	return;
}

inline std::string
hexdump_t::get_line(std::size_t cnt) const
{
	const std::string 	brk(' ', static_cast< char >(m_break));
	unsigned char		unp(m_unprint);
	std::string			retval("");

	if ( LLONG_MAX <= m_data.size() )
		retval += fmt("%.32X    ", cnt);
	else if ( LONG_MAX <= m_data.size() )
		retval += fmt("%.16X    ", cnt);
	else if ( SHRT_MAX <= m_data.size() )
		retval += fmt("%.8X    ", cnt);
	else
		retval += fmt("%.4X    ", cnt);

	if ( cnt > m_data.size() )
		throw std::runtime_error("hexdump_t::get_line(): Invalid index specified");

	if ( ( m_data.size() - cnt ) >= m_len ) {
		for ( std::size_t off = 0; off < m_len; off++ )
			if ( off == m_break )
				retval += fmt("   %.2X ", m_data.at(cnt + off));
			else
				retval += fmt("%.2X ", m_data.at(cnt + off));

		for ( std::size_t off = 0; off < m_len; off++ )
			if ( !std::isprint(m_data.at(cnt + off)) )
				retval += fmt("%c", unp);
			else
				retval += fmt("%c", m_data.at(cnt + off));

	} else {
		std::size_t len(0);

		for ( std::size_t off = 0; off < ( m_data.size() - cnt ); off++ )
			if ( off == m_break )
				retval += fmt("   %.2X ", m_data.at(cnt + off));
			else
				retval += fmt("%.2X ", m_data.at(cnt + off));

		// line length is 2 hex characters plus one space
		// per byte, so 3 bytes for each printed character
		// furthermore if we are above the break then we
		// need to account for those 3 bytes as well.
		if ( m_data.size() - cnt > m_break )
			len = m_len * 3 - ( ( m_data.size() - cnt ) * 3 );
		else
			len = m_len * 3 - ( ( m_data.size() - cnt ) * 3 ) + 3;

		for ( std::size_t off = len; off != 0; off-- )
			retval += " ";

		for ( std::size_t off = 0; off < ( m_data.size() - cnt ); off++ )
			if ( !std::isprint(m_data.at(cnt + off)) )
				retval += fmt("%c", m_unprint);
			else
				retval += fmt("%c", m_data.at(cnt + off));
	}

	return retval;
}

std::string
hexdump_t::to_string(void) const
{
	std::string retval("");

	if ( m_data.size() > m_len ) {
		std::size_t idx = 0;

		for ( ; idx < ( m_data.size() - m_len ); idx += m_len ) {
			retval += get_line(idx);
			retval += "\r\n";
		}

		retval += get_line(idx);

	} else
		retval += get_line(0);

	return retval;
}