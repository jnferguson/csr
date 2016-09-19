#include "asnone.hpp"

#include <climits>

template <typename T>
T swap_endian(T u)
{
	static_assert ( CHAR_BIT == 8, "CHAR_BIT != 8" );

	union
	{
		T u;
		unsigned char u8[ sizeof(T) ];
	} source, dest;

	source.u = u;

	for ( size_t k = 0; k < sizeof(T); k++ )
		dest.u8[ k ] = source.u8[ sizeof(T) - k - 1 ];

	return dest.u;
}

tlv_t::tlv_t(void) : m_class(0), m_encoding(0), m_tag(0), m_indefinite(false)
{
	return;
}

tlv_t::tlv_t(const uint8_t cla, const uint8_t enc, const uint8_t tag, const bool indef)
	: m_class(cla), m_encoding(enc), m_tag(tag), m_indefinite(indef)
{
	return;
}

tlv_t::~tlv_t(void)
{
	m_data.clear();
	m_length.clear();
	m_class = 0;
	m_encoding = 0;
	m_tag = 0;
	return;
}


uint8_t 
tlv_t::tag(void) const
{
	return m_tag & 0x1F;
}

void 
tlv_t::tag(const uint8_t v)
{
	m_tag = ( v & 0x1F );
	return;
}

uint8_t
tlv_t::tag_class(void) const
{
	return m_class;
}

void
tlv_t::tag_class(const uint8_t v)
{
	m_class = ( v & ASN1_PRIVATE_CLASS );
	return;
}

bool
tlv_t::universal_class(void) const
{
	return m_class == ASN1_UNIVERSAL_CLASS;
}

bool
tlv_t::application_class(void) const
{
	return m_class == ASN1_APPLICATION_CLASS;
}

bool
tlv_t::context_specific_class(void) const
{
return m_class == ASN1_CONTEXT_SPECIFIC_CLASS;
}

bool
tlv_t::private_class(void) const
{
	return m_class == ASN1_PRIVATE_CLASS;
}

void
tlv_t::encoding(const uint8_t v)
{
	m_encoding = ( v & ASN1_CONSTRUCTED );
	return;
}

bool
tlv_t::primitive(void) const
{
	return m_encoding == ASN1_PRIMITIVE;
}

bool
tlv_t::constructed(void) const
{
	return m_encoding == ASN1_CONSTRUCTED;
}

void
tlv_t::indefinite(const bool set)
{
	if ( true == set ) {
		m_length.clear();
		m_length.push_back(ASN1_LENGTH_FORM_MASK);
		m_indefinite = true;

	} else {
		m_length.clear();
		m_indefinite = false;
	}

	return;
}

void
tlv_t::length(const std::size_t v, bool indef)
{

	if ( true == indef ) {		// indefinite
		indefinite(true);
		return;
	}

	m_length.clear();

	if ( 127 >= v )				// definite, short
		m_length.push_back(static_cast< char >(v & 0x7F));
	else {						// definite, long
		std::size_t				cnt(0);
		std::size_t				val(v);
		std::vector< uint8_t >	tmp;

		for ( ; val > 0; cnt++ )
			val >>= 8;

		if ( 126 < cnt )
			throw std::runtime_error("Unhandled edge case in definite long form length encoding");

		m_length.push_back(ASN1_LENGTH_FORM_MASK | static_cast< char >(cnt & 0x7F));
		val = v;

		while ( cnt-- > 0 ) {
			tmp.push_back(val & 0xFF);
			//m_length.push_back(val & 0xFF);
			val >>= 8;
		}

		if ( 0 == tmp.size() || ( static_cast< std::size_t >( ( std::numeric_limits< signed long >::max )( ) ) < tmp.size() ) )
			throw std::runtime_error("");

		for ( signed long long idx = tmp.size() - 1; idx >= 0; idx-- )
			m_length.push_back(tmp.at(static_cast< std::size_t >( idx )));
	}

	return;
}

std::vector< uint8_t >&
tlv_t::get_length(void)
{
	return m_length;
}

std::vector< uint8_t >&
tlv_t::get_data(void)
{
	return m_data;
}

std::string
tlv_t::to_string(void)
{
	std::string ret("");
	uint8_t		byte(0);

	byte |= ( ( m_class << 6 ) & ( 0x03 << 6 ) );
	byte |= ( ( m_encoding << 5 ) & ( 0x01 << 5 ) );
	byte |= ( m_tag & 0x1F );
	ret += byte;

	if ( 0 == m_length.size() )
		length(m_data.size());

	for ( std::size_t idx = 0; idx < m_length.size(); idx++ )
		ret += m_length.at(idx);
	//for ( auto& val : m_length )
	//	ret += val;

	for ( std::size_t idx = 0; idx < m_data.size(); idx++ )
		ret += m_data.at(idx);

	//for ( auto& val : m_data )
	//	ret += val;

	return ret;
}

boolean_t::boolean_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_BOOLEAN), m_value(false)
{
	return;
}

boolean_t::~boolean_t(void) 
{
	return;
}

bool 
boolean_t::is_true(void) 
{ 
	return true == m_value; 
}

bool 
boolean_t::is_false(void) 
{ 
	return false == m_value; 
}

bool 
boolean_t::value(void) 
{ 
	return m_value; 
}

void 
boolean_t::value(const bool v) 
{ 
	m_value = v; 
	return; 
}

std::string 
boolean_t::to_string(void)
{
	m_data.clear();
	m_length.clear();

	if ( true == m_value )
		m_data.push_back(0x01);
	else
		m_data.push_back(0x00);

	return tlv_t::to_string();
}

eoc_t::eoc_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_EOC_TYPE)
{
	return;
}

eoc_t::~eoc_t(void) 
{
	return;
}

integer_t::integer_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_INTEGER_TYPE)
{
	return;
}

integer_t::~integer_t(void) 
{
	return;
}

// Integers can be positive or negative and
// utilize the first octets highest order bit
// to discern whether it is positive or negative.
// If the integer is intended to be positive and
// it has its highest order bit set in the first
// octet, then you must prefix the integer with
// a zero byte.
std::string
integer_t::to_string(void)
{
	std::vector< uint8_t > tmp;

	if ( 0 == m_data.size() )
		return tlv_t::to_string();

	if ( 0 != ( m_data.at(0) & 0x80 ) )
		tmp.push_back(0x00);

	tmp.insert(tmp.end(), m_data.begin(), m_data.end());
	m_data = tmp;

	length(m_data.size());
	return tlv_t::to_string();
}

// constructed bit strings as described in 8.6.2.1 et seq in T-REC-X.690-200811
bit_string_t::bit_string_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_BIT_STRING)
{
	return;
}

bit_string_t::~bit_string_t(void)
{
	return;
}

std::size_t
bit_string_t::remainder_bits(void) const
{
	return m_remainder;
}

void
bit_string_t::remainder_bits(const std::size_t v)
{
	m_remainder = (v & 7);
	return;
}

// XXX FIXME - 
// the other encoding type for octet strings
// exceeding 1000 octets in length is not
// supported.
std::string 
bit_string_t::to_string(void)
{
	std::vector< uint8_t > tmp;

	tmp.push_back(m_remainder);
	tmp.insert(tmp.end(), m_data.begin(), m_data.end());
	m_data = tmp;

	return tlv_t::to_string();
	//m_data.push_back(0x00);
	//return tlv_t::to_string();
}

// The segmented usage of this class as documented in 8.7 et seq in T-REC-X.690-200811
// is not supported here.
octet_string_t::octet_string_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_OCTET_STRING)
{
	return;
}

octet_string_t::~octet_string_t(void) 
{
	return;
}

std::vector< std::string >
oid_t::split(const char* str, const char c)
{
	std::vector< std::string > result;

	if ( nullptr == str )
		throw std::invalid_argument("oid_t::split(): invalid parameter (impossible code path)");

	do {
		const char* begin = str;

		while ( *str != c && *str )
			str++;

		result.push_back(std::string(begin, str));
	} while ( 0 != *str++ );

	return result;
}

oid_t::oid_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_OBJECT_IDENTIFIER)
{
	return;
}

oid_t::~oid_t(void) 
{
	return;
}

// XXX FIXME -
// this assumes the native host machine stores integers
// in little endian format, which is probably correct
// but not necessarily correct.
// It also puts an upper-bound on the number of subidentifiers
// and also the maximum value of each subidentifier;
// which probably exceeds the maximum number that the specification
// requires in the former and likely below the maximum in the later. 
bool
oid_t::set_oid(const std::string& oid)
{
	std::vector< std::string >	vals(split(oid.c_str()));
	std::vector< uint8_t >		tmp;
	unsigned long long			x(0), y(0);

	// i sincerely dislike that none of the string/ascii to integer related
	// functions really have a sane way of implying an error-- std::strtoull()
	// returns 0 on failure and its not clear how i am to differentiate that
	// from when you pass '0' as a parameter; if the value exceeds the ULLONG_MAX
	// then ULLONG_MAX is returned, which could be an overflow or it could be
	// because you specified a parameter of ULLONG_MAX. These sorts of catch-22s
	// are the ideal argument for exception throwing.

	if ( 2 > vals.size() )
		throw std::runtime_error("oid_t::set_oid(): OID encoding mandates that the first two octets be present");

	x = std::strtoull(vals.at(0).c_str(), nullptr, 0);
	y = std::strtoull(vals.at(1).c_str(), nullptr, 0);

	if ( x > ULLONG_MAX - y )
		throw std::runtime_error("oid_t::set_oid(): Result of requisite arithmetic on first two octets would result in overflow");

	x = ( x * 40 ) + y;

	m_data.clear();

	if ( 0x7F >= x )
		m_data.push_back(static_cast< uint8_t >( x ));
	else {
		uint8_t byte(0x00);

		while ( 0 < x ) {
			byte = x & 0x7F;
			tmp.push_back(byte);
			x >>= 7;
		}

		if ( 0 == tmp.size() || 
			static_cast< std::size_t >( ( std::numeric_limits< signed long >::max )( ) ) < tmp.size() )
			throw std::runtime_error("");

		for ( signed long idx = tmp.size() - 1; idx >= 0; idx-- ) {
			if ( 0 != idx )
				m_data.push_back(tmp.at(static_cast< std::size_t >( idx )) | 0x80);
			else
				m_data.push_back(tmp.at(static_cast< std::size_t >( idx )));
		}
	}

	for ( std::size_t idx = 2; idx < vals.size(); idx++ ) {
		x = std::strtoull(vals.at(idx).c_str(), nullptr, 0);

		tmp.clear();

		if ( 0x7F >= x )
			m_data.push_back(static_cast< uint8_t >( x ));
		else {
			uint8_t byte(0x00);

			while ( 0 < x ) {
				byte = x & 0x7F;
				tmp.push_back(byte);
				x >>= 7;
			}

			if ( 0 == tmp.size() || 
				static_cast< std::size_t >( ( std::numeric_limits< signed long >::max )( ) ) < tmp.size() )
				throw std::runtime_error("");

			for (signed long idx = tmp.size()-1; idx >= 0; idx--) {
				if ( 0 != idx )
					m_data.push_back(tmp.at(static_cast< std::size_t >( idx )) | 0x80);
				else
					m_data.push_back(tmp.at(static_cast< std::size_t >( idx )));
			}
		}
	}

	return true;
}

utf8_string_t::utf8_string_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_UTF8_STRING)
{
	return;
}

utf8_string_t::~utf8_string_t(void) 
{
	return;
}

printable_string_t::printable_string_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_PRINTABLE_STRING)
{
	return;
}

printable_string_t::~printable_string_t(void)
{
	return;
}

null_t::null_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_PRIMITIVE, ASN1_NULL)
{
	return;
}

null_t::~null_t(void)
{
	return;
}

set_t::set_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_CONSTRUCTED, ASN1_SET)
{
	return;
}

set_t::~set_t(void) 
{
	return;
}

std::vector< tlv_t* >&
set_t::contents(void) 
{
	return m_contents;
}

std::string
set_t::to_string(void) 
{
	std::size_t len(0);
	std::string str("");
	uint8_t		byte(0);

	for (std::size_t idx = 0; idx < m_contents.size(); idx++ ) {
		tlv_t*		tmp_tlv(nullptr);
		set_t*		tmp_set(nullptr);
		sequence_t* tmp_seq = dynamic_cast< sequence_t* >( m_contents.at(idx) );

		if ( nullptr == tmp_seq ) {
			tmp_set = dynamic_cast< set_t* >( m_contents.at(idx) );
		
			if ( nullptr == tmp_set ) {
				tmp_tlv = dynamic_cast< tlv_t* >( m_contents.at(idx) );

				str = tmp_tlv->to_string();
			} else
				str = tmp_set->to_string();
		} else
			str = tmp_seq->to_string();

		if ( str.length() > UINT_MAX || len > UINT_MAX - str.length() )
			throw std::overflow_error("Integer overflow while processing absurdly large objects");

		len += str.length();
		std::copy(str.begin(), str.end(), std::back_inserter(m_data));
	}

	if ( 0 == m_length.size() )
		length(len);

	str.clear();

	byte |= ( ( m_class << 6 ) & ( 0x03 << 6 ) );
	byte |= ( ( m_encoding << 5 ) & ( 0x01 << 5 ) );
	byte |= ( m_tag & 0x1F );

	str += byte;

	for ( auto& tmp : m_length )
		str.push_back(tmp);

	for ( auto& tmp : m_data )
		str.push_back(tmp);

	m_data.clear();
	m_length.clear();
	return str;
}

sequence_t::sequence_t(void) : tlv_t(ASN1_UNIVERSAL_CLASS, ASN1_CONSTRUCTED, ASN1_SEQUENCE)
{
	return;
}

sequence_t::~sequence_t(void) 
{
	m_contents.clear();
	return;
}

std::vector< tlv_t* >&
sequence_t::contents(void) 
{
	return m_contents;
}

std::string
sequence_t::to_string(void)
{
	std::size_t len(0);
	std::string str("");
	uint8_t		byte(0);

	for ( std::size_t idx = 0; idx < m_contents.size(); idx++ ) {
		tlv_t*		tmp_tlv(nullptr);
		set_t*		tmp_set(nullptr);
		sequence_t* tmp_seq = dynamic_cast< sequence_t* >( m_contents.at(idx) );

		if ( nullptr == tmp_seq ) {
			tmp_set = dynamic_cast< set_t* >( m_contents.at(idx) );

			if ( nullptr == tmp_set ) {
				tmp_tlv = dynamic_cast< tlv_t* >( m_contents.at(idx) );

				str = tmp_tlv->to_string();
			} else
				str = tmp_set->to_string();
		} else
			str = tmp_seq->to_string();

		if ( str.length() > UINT_MAX || len > UINT_MAX - str.length() )
			throw std::overflow_error("Integer overflow while processing absurdly large objects");

		len += str.length();
		std::copy(str.begin(), str.end(), std::back_inserter(m_data));
	}

	if ( 0 == m_length.size() )
		length(len);

	str.clear();

	byte |= ( ( m_class << 6 ) & ( 0x03 << 6 ) );
	byte |= ( ( m_encoding << 5 ) & ( 0x01 << 5 ) );
	byte |= ( m_tag & 0x1F );

	str += byte;

	for ( auto& tmp : m_length )
		str.push_back(tmp);

	for ( auto& tmp : m_data )
		str.push_back(tmp);

	m_data.clear();
	m_length.clear();
	return str;
}