#include "x509_request.hpp"

distinguished_name_t::distinguished_name_t(const DN_ATTRIBUTES_T& dat, const std::string& n = std::string("")) : m_name(n)
{
	m_oid.set_oid(g_dn_attributes[ dat ].second);
	return;
}

distinguished_name_t::~distinguished_name_t(void) 
{ 
	return; 
}

std::string 
distinguished_name_t::name(void)
{ 
	return m_name; 
}

void 
distinguished_name_t::name(const std::string& n) 
{ 
	m_name = n; 
	return; 
}

set_t
distinguished_name_t::to_set(void)
{
	set_t				set;
	sequence_t*			seq(new sequence_t);
	oid_t*				oid(new oid_t(m_oid));
	printable_string_t*	str(new printable_string_t);
	std::string			ret("");

	if ( 0 == m_name.length() )
		throw std::runtime_error("distinguished_name_t::to_string(): Called without name being initialized.");

	for ( auto& byte : m_name )
		str->get_data().push_back(byte);

	seq->contents().push_back(oid);
	seq->contents().push_back(str);
	set.contents().push_back(seq);
	return set;
}

std::string
distinguished_name_t::to_string(void)
{
	set_t				set;
	sequence_t*			seq(new sequence_t);
	oid_t*				oid(new oid_t(m_oid));
	printable_string_t*	str(new printable_string_t);
	std::string			ret("");

	if ( 0 == m_name.length() )
		throw std::runtime_error("distinguished_name_t::to_string(): Called without name being initialized.");

	for ( auto& byte : m_name )
		str->get_data().push_back(byte);

	//oid->set_oid(g_dn_attributes[ X520_COUNTRYNAME ].second);
	seq->contents().push_back(oid);
	seq->contents().push_back(str);
	set.contents().push_back(seq);

	ret = set.to_string();

	delete seq;
	delete oid;
	delete str;

	return ret;
}

dn_common_name_t::dn_common_name_t(void) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_COMMONNAME) 
{ 
	return; 
}

dn_common_name_t::dn_common_name_t(const std::string& n) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_COMMONNAME, n) 
{ 
	return; 
}

dn_common_name_t::dn_common_name_t(const char* n) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_COMMONNAME, std::string(n)) 
{ 
	return; 
}
 
dn_common_name_t::~dn_common_name_t(void) 
{ 
	return; 
}

std::string& 
dn_common_name_t::common_name(void) 
{ 
	return m_name; 
}

void 
dn_common_name_t::common_name(const std::string& v) 
{ 
	m_name = v; 
	return; 
}

dn_country_name_t::dn_country_name_t::dn_country_name_t(void)
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_COUNTRYNAME) 
{ 
	return; 
}

dn_country_name_t::dn_country_name_t(const std::string& n)
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_COUNTRYNAME, n) 
{ 
	return; 
}

dn_country_name_t::dn_country_name_t(const char* n) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_COUNTRYNAME, std::string(n)) 
{ 
	return; 
}

dn_country_name_t::~dn_country_name_t(void)
{ 
	return; 
}

std::string& dn_country_name_t::country_name(void) 
{ 
	return m_name; 
}

void 
dn_country_name_t::country_name(const std::string& v) 
{ 
	m_name = v; 
	return; 
}

dn_locality_name_t::dn_locality_name_t::dn_locality_name_t(void)
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_LOCALITYNAME) 
{ 
	return; 
}

dn_locality_name_t::dn_locality_name_t::dn_locality_name_t(const std::string& n)
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_LOCALITYNAME, n) 
{ 
	return; 
}

dn_locality_name_t::dn_locality_name_t(const char* n)
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_LOCALITYNAME, std::string(n)) 
{ 
	return; 
}

dn_locality_name_t::~dn_locality_name_t(void) 
{ 
	return; 
}

std::string& 
dn_locality_name_t::locality_name(void) 
{ 
	return m_name; 
}

void 
dn_locality_name_t::locality_name(const std::string& v) 
{ 
	m_name = v; 
	return; 
}

dn_organization_name_t::dn_organization_name_t(void) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_ORGANIZATIONNAME) 
{ 
	return; 
}

dn_organization_name_t::dn_organization_name_t(const std::string& n) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_ORGANIZATIONNAME, n) 
{ 
	return; 
}

dn_organization_name_t::dn_organization_name_t(const char* n)
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_ORGANIZATIONNAME, std::string(n)) 
{ 
	return; 
}

dn_organization_name_t::~dn_organization_name_t(void)
{ 
	return; 
}

std::string& 
dn_organization_name_t::organization_name(void) 
{ 
	return m_name; 
}

void 
dn_organization_name_t::organization_name(const std::string& v) 
{ 
	m_name = v; 
	return; 
}


dn_state_or_province_name_t::dn_state_or_province_name_t(void) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_STATEORPROVINCENAME) 
{ 
	return; 
}

dn_state_or_province_name_t::dn_state_or_province_name_t(const std::string& n) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_STATEORPROVINCENAME, n) 
{ 
	return; 
}

dn_state_or_province_name_t::dn_state_or_province_name_t(const char* n) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_STATEORPROVINCENAME, std::string(n)) 
{ 
	return; 
}

dn_state_or_province_name_t::~dn_state_or_province_name_t(void) 
{ 
	return; 
}

std::string& 
dn_state_or_province_name_t::state_or_province_name(void) 
{ 
	return m_name; 
}

void 
dn_state_or_province_name_t::state_or_province_name(const std::string& v) 
{ 
	m_name = v; 
	return; 
}

dn_organizational_unit_name_t::dn_organizational_unit_name_t(void) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_ORGANIZATIONUNIT) 
{ 
	return;
}

dn_organizational_unit_name_t::dn_organizational_unit_name_t(const std::string& n) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_ORGANIZATIONUNIT, n) 
{ 
	return; 
}

dn_organizational_unit_name_t::dn_organizational_unit_name_t(const char* n) 
	: distinguished_name_t(DN_ATTRIBUTES_T::X520_ORGANIZATIONUNIT, std::string(n)) 
{ 
	return; 
}

dn_organizational_unit_name_t::~dn_organizational_unit_name_t(void) 
{ 
	return; 
}

std::string& 
dn_organizational_unit_name_t::organizational_unit_name(void) 
{ 
	return m_name; 
}

void 
dn_organizational_unit_name_t::organizational_unit_name(const std::string& v) 
{ 
	m_name = v; 
	return; 
}

pki_info_t::pki_info_t(const std::size_t siz) : m_rsa(siz)
{

	m_modulus			= m_rsa.public_modulus();
	m_public_exponent	= m_rsa.public_exponent();

	return;
}

pki_info_t::~pki_info_t(void) 
{ 
	return;
}

bool 
pki_info_t::sha256_rsa_sign(const std::string& v, std::vector< uint8_t >& r)
{
	return m_rsa.sign(v, r);
}

std::string
pki_info_t::to_string(void)
{
	sequence_t		outer_seq, inner_seq, embed_seq;
	oid_t			oid;
	null_t			nul;
	integer_t		exponent, modulus;
	bit_string_t	bs;
	std::string		ret("");

	oid.set_oid(RSA_ENCRYPTION_OID);
	inner_seq.contents().push_back(&oid);
	inner_seq.contents().push_back(&nul);
	outer_seq.contents().push_back(&inner_seq);

	for ( std::size_t idx = 0; idx < m_modulus.size(); idx++ )
		modulus.get_data().push_back(m_modulus[ idx ] & 0xFF);

	modulus.length(modulus.get_data().size());

	for ( std::size_t idx = 0; idx < m_public_exponent.size(); idx++ )
		exponent.get_data().push_back(m_public_exponent[ idx ] & 0xFF);

	exponent.length(exponent.get_data().size());

	embed_seq.contents().push_back(&modulus);
	embed_seq.contents().push_back(&exponent);

	for ( auto& byte : embed_seq.to_string() )
		bs.get_data().push_back(byte);

	outer_seq.contents().push_back(&bs);
	ret = outer_seq.to_string();
	return ret;
}

sequence_t*
pki_info_t::to_sequence(void)
{
	sequence_t*		outer_seq(new sequence_t);
	sequence_t*		inner_seq(new sequence_t);
	sequence_t		embed_seq;
	oid_t*			oid(new oid_t);
	null_t*			nul(new null_t);
	integer_t*		exponent(new integer_t);
	integer_t*		modulus(new integer_t);
	bit_string_t*	bs(new bit_string_t);
	std::string		ret("");

	oid->set_oid(RSA_ENCRYPTION_OID);
	inner_seq->contents().push_back(oid);
	inner_seq->contents().push_back(nul);
	outer_seq->contents().push_back(inner_seq);

	for ( std::size_t idx = 0; idx < m_modulus.size(); idx++ )
		modulus->get_data().push_back(m_modulus[ idx ] & 0xFF);

	modulus->length(modulus->get_data().size());

	for ( std::size_t idx = 0; idx < m_public_exponent.size(); idx++ )
		exponent->get_data().push_back(m_public_exponent[ idx ] & 0xFF);

	exponent->length(exponent->get_data().size());

	embed_seq.contents().push_back(modulus);
	embed_seq.contents().push_back(exponent);


	// so as I understand it, DER forbids the 
	// encoding of a sequence as a child element
	// to a bitstring, however as per the norm in
	// computing that doesn't allow for the most
	// common use cases, wherein a public key 
	// consists of more than one value.
	// As a result of this, an illegal DER encoding
	// is the normal set of circumstances and I've
	// seen some explanations about this which seem
	// to imply that essentially the data is double 
	// encoding so that the sequence is interpreted
	// as bitstring data, which just seems wrong
	// or at least a faulty explanation that doesnt
	// entirely make sense. That said, in keeping
	// with that, we embed the data inclusive of its
	// sequence as data to the bitstring.
	//
	// Thus we do not need use until free memory
	// for the object 'embed_seq' nor its 
	// contents because the data is embedded inside
	// of the bitstring.
	for ( auto& byte : embed_seq.to_string() )
		bs->get_data().push_back(byte);

	outer_seq->contents().push_back(bs);
	return outer_seq;
}

algorithm_identifier_t::algorithm_identifier_t(void) 
{ 
	return;
}

algorithm_identifier_t::~algorithm_identifier_t(void) 
{ 
	return;
}

std::string
algorithm_identifier_t::to_string(void)
{
	sequence_t		seq;
	oid_t			oid;
	null_t			nul;

	oid.set_oid(SHA256_RSA_ENCRYPTION);
	seq.contents().push_back(&oid);
	seq.contents().push_back(&nul);

	return seq.to_string();
}

sequence_t
algorithm_identifier_t::to_sequence(void)
{
	sequence_t		seq;
	oid_t*			oid(new oid_t);
	null_t*			nul(new null_t);

	oid->set_oid(SHA256_RSA_ENCRYPTION);
	seq.contents().push_back(oid);
	seq.contents().push_back(nul);

	return seq;
}

certificate_request_info_t::certificate_request_info_t(void) 
{ 
	return; 
}

certificate_request_info_t::~certificate_request_info_t(void) 
{ 
	return; 
}

integer_t& 
certificate_request_info_t::version(void) 
{ 
	return m_version; 
}

void 
certificate_request_info_t::version(const uint8_t& v) 
{ 
	m_version.get_data().push_back(v); 
	return;
}

void 
certificate_request_info_t::add_subject_info(distinguished_name_t& v) 
{
	m_subject.push_back(v); 
	return;
}

std::vector< distinguished_name_t >& 
certificate_request_info_t::subject(void) 
{ 
	return m_subject; 
}

pki_info_t& 
certificate_request_info_t::pki_info(void) 
{ 
	return m_pki_info; 
}

x509_extensions_t& 
certificate_request_info_t::extensions(void)
{
	return m_extensions;
}

void
certificate_request_info_t::add_extension(extension_t& v)
{
	m_extensions.add_extension(v.to_sequence());
	return;
}

std::string
certificate_request_info_t::to_string(void)
{
	sequence_t	seq;
	sequence_t*	seq2(new sequence_t);
//	sequence_t*	seq3(new sequence_t); 

	seq.contents().push_back(&m_version);
	seq.contents().push_back(seq2);
//	seq.contents().push_back(seq3);
	seq.contents().push_back(m_pki_info.to_sequence());
	//seq3->contents().push_back(m_pki_info.to_sequence());
	seq.contents().push_back(new set_t(m_extensions.to_set()));

	for ( std::size_t idx = 0; idx < m_subject.size(); idx++ )
		seq2->contents().push_back(new set_t(m_subject.at(idx).to_set()));

	
	return seq.to_string();
}

std::string
certificate_request_info_t::to_signing_string(void)
{
	sequence_t	seq, seq2; // , seq3;
	set_t		set;

	seq.contents().push_back(&m_version);
	seq.contents().push_back(&seq2);
//	seq.contents().push_back(&seq3);
	seq.contents().push_back(m_pki_info.to_sequence());
	//seq3.contents().push_back(m_pki_info.to_sequence());
	seq.contents().push_back(&m_extensions.to_signing_set());

	for ( std::size_t idx = 0; idx < m_subject.size(); idx++ )
		seq2.contents().push_back(new set_t(m_subject.at(idx).to_set()));

	return seq.to_string(); 
}

sequence_t
certificate_request_info_t::to_sequence(void)
{
	std::string ret("");
	sequence_t	seq;
	sequence_t*	seq2(new sequence_t);
//	sequence_t*	seq3(new sequence_t); 

	seq.contents().push_back(&m_version);
	seq.contents().push_back(seq2);
//	seq.contents().push_back(seq3);
	seq.contents().push_back(m_pki_info.to_sequence());
// seq3->contents().push_back(m_pki_info.to_sequence());
	seq.contents().push_back(&m_extensions.to_set());

	for ( std::size_t idx = 0; idx < m_subject.size(); idx++ )
		seq2->contents().push_back(new set_t(m_subject.at(idx).to_set()));

	return seq;
}

extension_t::extension_t(void) 
{ 
	return;
}


extension_t::extension_t(const std::string& oid) 
{
	m_oid.set_oid(oid);
	return;
}

extension_t::~extension_t(void) 
{ 
	return;
}

oid_t&
extension_t::oid(void)
{
	return m_oid;
}

void
extension_t::oid(const std::string& v)
{
	m_oid.set_oid(v);
	return;
}

octet_string_t&
extension_t::octet_string(void)
{
	return m_oct;
}

/*std::string
extension_t::to_string(void)
{
	sequence_t		seq;

	seq.contents().push_back(&m_oid);
	seq.contents().push_back(&m_oct);

	return seq.to_string();
}

sequence_t
extension_t::to_sequence(void)
{
	sequence_t		seq;
	oid_t*			oid(new oid_t(m_oid));
	octet_string_t*	oct(new octet_string_t(m_oct));

	seq.contents().push_back(oid);
	seq.contents().push_back(oct);

	return seq;
}*/

basic_constraints_t::basic_constraints_t(void) : extension_t(EXTENSION_BASIC_CONSTRAINTS), m_ca(false), m_length(0)
{
	return;
}

basic_constraints_t::~basic_constraints_t(void)
{
	return;
}

bool 
basic_constraints_t::ca(void) const
{
	return m_ca;
}

void 
basic_constraints_t::ca(const bool v)
{
	m_ca = v;
}

std::size_t 
basic_constraints_t::path_length(void) const
{
	return m_length;
}

void 
basic_constraints_t::path_length(const std::size_t v)
{
	m_length = v;
	return;
}

std::string
basic_constraints_t::to_string(void)
{
	sequence_t	inner, seq;
	integer_t	len;
	boolean_t	boo;
	std::size_t	val(m_length), idx(0);

	boo.value(m_ca);
	seq.contents().push_back(&boo);

	if ( true == m_ca ) {
		while ( 0 < m_length ) {
			idx++;
			len.get_data().push_back(val & 0xFF);
			val >>= 8;
		}

		len.length(idx);
		seq.contents().push_back(&len);
	}


	for ( auto& byte : seq.to_string() )
		m_oct.get_data().push_back(byte);

	inner.contents().push_back(&m_oid);
	inner.contents().push_back(&m_oct);
	return inner.to_string();
}

sequence_t
basic_constraints_t::to_sequence(void)
{
	sequence_t	inner;
	sequence_t* seq(new sequence_t);
	integer_t*	len(new integer_t);
	boolean_t*	boo(new boolean_t);
	std::size_t	val(m_length), idx(0);

	boo->value(m_ca);
	seq->contents().push_back(boo);

	if ( true == m_ca ) {
		while ( 0 < m_length ) {
			idx++;
			len->get_data().push_back(val & 0xFF);
			val >>= 8;
		}

		len->length(idx);
		seq->contents().push_back(len);
	} else {
		seq->contents().clear();
	}

	for ( auto& byte : seq->to_string() )
		m_oct.get_data().push_back(byte);

	inner.contents().push_back(&m_oid);
	inner.contents().push_back(&m_oct);
	return inner;
}


key_usage_t::key_usage_t(void) :	extension_t(EXTENSION_KEY_USAGE), m_signature(true), m_nonrepudiation(true), 
									m_key_encipherment(true), m_data_encipherment(true), m_key_agreement(true),
									m_key_cert_sign(true), m_crl_sign(true)
{
	return;
}

key_usage_t::~key_usage_t(void)
{
	return;
}

bool 
key_usage_t::signature(void) const
{ 
	return m_signature; 
}

void 
key_usage_t::signature(const bool v) 
{ 
	m_signature = v; 
	return; 
}

bool 
key_usage_t::nonrepudiation(void) const
{ 
	return m_nonrepudiation; 
}

void 
key_usage_t::nonrepudiation(const bool v) 
{ 
	m_nonrepudiation = v; 
	return; 
}

bool 
key_usage_t::key_encipherment(void) const
{ 
	return m_key_encipherment; 
}

void 
key_usage_t::key_encipherment(const bool v) 
{ 
	m_key_encipherment = v; 
	return; 
}

bool 
key_usage_t::data_encipherment(void) const
{ 
	return m_data_encipherment; 
}

void 
key_usage_t::data_encipherment(const bool v) 
{ 
	m_data_encipherment = v; 
	return; 
}

bool 
key_usage_t::key_agreement(void) const
{ 
	return m_key_agreement; 
}

void 
key_usage_t::key_agreement(const bool v) 
{ 
	m_key_agreement = v; 
	return; 
}

bool 
key_usage_t::key_cert_sign(void) const
{ 
	return m_key_cert_sign; 
}

void 
key_usage_t::key_cert_sign(const bool v) 
{ 
	m_key_cert_sign = v; 
	return; 
}

bool 
key_usage_t::crl_sign(void) const
{ 
	return m_crl_sign; 
}

void 
key_usage_t::crl_sign(const bool v) 
{ 
	m_crl_sign = v; 
	return; 
}

std::string
key_usage_t::to_string(void)
{
	uint8_t			val(0), mlen(0);
	bit_string_t	bit;
	sequence_t		seq;

	if ( true == m_signature )
		val |= ( 0x01 );
	if ( true == m_nonrepudiation )
		val |= ( 0x01 << 1 );
	if ( true == m_key_encipherment )
		val |= ( 0x01 << 2 );
	if ( true == m_data_encipherment )
		val |= ( 0x01 << 3 );
	if ( true == m_key_agreement )
		val |= ( 0x01 << 4 );
	if ( true == m_key_cert_sign )
		val |= ( 0x01 << 5 );
	if ( true == m_crl_sign )
		val |= ( 0x01 << 6 );

	for ( uint8_t idx = 0; idx < 7; idx++ )
		if ( ( val >> idx ) & 0x01 )
			mlen = idx;

	mlen = 8 - mlen;
	bit.get_data().push_back(mlen);
	bit.get_data().push_back(val);

	for ( auto& byte : bit.get_data() )
		m_oct.get_data().push_back(byte);

	seq.contents().push_back(&m_oid);
	seq.contents().push_back(&m_oct);
	return seq.to_string();
}

sequence_t
key_usage_t::to_sequence(void)
{
	uint8_t			val(0), mlen(0);
	bit_string_t*	bit(new bit_string_t);
	sequence_t		seq;

	if ( true == m_signature )
		val |= ( 0x01 << 7);
	if ( true == m_nonrepudiation )
		val |= ( 0x01 << 6 );
	if ( true == m_key_encipherment )
		val |= ( 0x01 << 5 );
	if ( true == m_data_encipherment )
		val |= ( 0x01 << 4 );
	if ( true == m_key_agreement )
		val |= ( 0x01 << 3 );
	if ( true == m_key_cert_sign )
		val |= ( 0x01 << 2 );
	if ( true == m_crl_sign )
		val |= ( 0x01 << 1 );

	for ( int8_t idx = 7; idx > 0; idx-- )
		if ( ( val >> idx ) & 0x01 )
			mlen = idx;

	//mlen = 8 - mlen;
	bit->remainder_bits(mlen); // +1);
	bit->get_data().push_back(val);

	for ( auto& byte : bit->to_string() )
		m_oct.get_data().push_back(byte);

	seq.contents().push_back(&m_oid);
	seq.contents().push_back(&m_oct);
	return seq;
}


dns_name_t::dns_name_t(void) : tlv_t(ASN1_CONTEXT_SPECIFIC_CLASS, ASN1_PRIMITIVE, ASN1_CONTEXT_SPECIFIC_TWO)
{
	return;
}

dns_name_t::~dns_name_t(void)
{
	return;
}

void
dns_name_t::add_name(const std::string& v)
{
	m_data.insert(m_data.end(), v.begin(), v.end());
}

void
dns_name_t::add_name(const char* v, std::size_t l)
{
	if ( nullptr == v || 0 == v )
		throw std::invalid_argument("Null pointer or zero length parameter name passed");

	for ( std::size_t idx = 0; idx < l; idx++ )
		m_data.push_back(v[ idx ]);

	return;
}

ip_address_t::ip_address_t(void) : tlv_t(ASN1_CONTEXT_SPECIFIC_CLASS, ASN1_PRIMITIVE, ASN1_CONTEXT_SPECIFIC_SEVEN)
{
	return;
}

ip_address_t::~ip_address_t(void)
{
	return;
}

void
ip_address_t::append(const uint8_t v)
{
	m_data.push_back(v);
	return;
}

void
ip_address_t::append(const uint16_t v)
{
	m_data.push_back(( v >> 8 ) & 0xFF);
	m_data.push_back(v & 0xFF);
	return;
}

void
ip_address_t::append(const uint32_t v)
{
	m_data.push_back(( v >> 24 ) & 0xFF);
	m_data.push_back(( v >> 16 ) & 0xFF);
	m_data.push_back(( v >> 8 ) & 0xFF);
	m_data.push_back(v & 0xFF);
	return;
}

void
ip_address_t::append(const uint64_t v)
{
	m_data.push_back(( v >> 56 ) & 0xFF);
	m_data.push_back(( v >> 48 ) & 0xFF);
	m_data.push_back(( v >> 40 ) & 0xFF);
	m_data.push_back(( v >> 32 ) & 0xFF);
	m_data.push_back(( v >> 24 ) & 0xFF);
	m_data.push_back(( v >> 16 ) & 0xFF);
	m_data.push_back(( v >> 8 ) & 0xFF);
	m_data.push_back(v & 0xFF);
	return;
}

void
ip_address_t::append(const std::vector< uint8_t >& v)
{
	m_data.insert(m_data.end(), v.begin(), v.end());
	return;
}

subject_altname_t::subject_altname_t(void) : extension_t(EXTENSION_SUBJECT_ALTNAME)
{
	return;
}

subject_altname_t::~subject_altname_t(void)
{
	return;
}

std::vector< tlv_t* >& 
subject_altname_t::contents(void) 
{ 
	return m_contents; 
}

std::string 
subject_altname_t::to_string(void)
{
	sequence_t	seq;

	seq.contents().push_back(&m_oid);

	for ( auto& value : m_contents ) {
		std::string val(value->to_string());

		for ( auto& byte : val )
			m_oct.get_data().push_back(byte);
	}

	seq.contents().push_back(&m_oct);

	return seq.to_string();
}

sequence_t 
subject_altname_t::to_sequence(void)
{
	sequence_t		seq;
	sequence_t*		inner(new sequence_t);
	oid_t*			oid(new oid_t(m_oid));
	octet_string_t*	oct(new octet_string_t);

	seq.contents().push_back(oid);

	for ( auto& value : m_contents )
		inner->contents().push_back(value);

	for ( auto& value : inner->to_string() )
		oct->get_data().push_back(value);

	/*for ( auto& value : m_contents ) {
		std::string val(value->to_string());

		for ( auto& byte : val )
			oct->get_data().push_back(byte);
	}*/

	seq.contents().push_back(oct);
	return seq;

}

x509_extensions_t::x509_extensions_t(void)
{
	return;
}

x509_extensions_t::~x509_extensions_t(void)
{
	m_set.contents().clear();

	for ( std::size_t idx = 0; idx < m_vec.size(); idx++ )
		delete m_vec.at(0);

	m_vec.clear();
	return;
}

void
x509_extensions_t::add_extension(sequence_t& seq)
{
	m_vec.push_back(new sequence_t(seq));

	//			for ( auto& ptr : seq.contents() )
	//				delete ptr;

	seq.contents().clear();
	return;

}

std::string
x509_extensions_t::to_signing_string(void)
{
	sequence_t*	seq(new sequence_t);
	oid_t*		oid(new oid_t);
	set_t*		set(new set_t);
	std::size_t	idx(0);
	
	m_set.get_data().clear();
	m_set.contents().clear();

	oid->set_oid(EXTENSION_REQUEST_PKCS9_VIA_CRMF);

	seq->contents().push_back(oid);
	seq->contents().push_back(set);

	for ( ; idx < m_vec.size(); idx++ )
		seq->contents().push_back(m_vec.at(idx));

	m_set.contents().push_back(seq);
	return m_set.to_string();
}

std::string
x509_extensions_t::to_string(void)
{
	sequence_t*	seq(new sequence_t); 
	sequence_t* inner(new sequence_t);
	oid_t*		oid(new oid_t);
	set_t*		set(new set_t);

	m_set.get_data().clear();
	m_set.contents().clear();

	oid->set_oid(EXTENSION_REQUEST_PKCS9_VIA_CRMF);

	seq->contents().push_back(oid);
	seq->contents().push_back(set);
	set->contents().push_back(inner);

	for ( std::size_t idx = 0; idx < m_vec.size(); idx++ )
		inner->contents().push_back(m_vec.at(idx));

	// this should equal 0xA0
	// (CONTEXT_SPECIFIC << 6|CONSTRUCTED << 5|0x00)
	m_set.tag(ASN1_CONTEXT_SPECIFIC_ZERO);
	m_set.tag_class(ASN1_CONTEXT_SPECIFIC_CLASS);
	m_set.encoding(ASN1_CONSTRUCTED);
	m_set.contents().push_back(seq);

	return m_set.to_string();
}

set_t&
x509_extensions_t::to_set(void)
{
	sequence_t*	seq(new sequence_t);
	sequence_t* inner(new sequence_t);
	oid_t*		oid(new oid_t);
	set_t*		set(new set_t);

	m_set.get_data().clear();
	m_set.contents().clear();

	oid->set_oid(EXTENSION_REQUEST_PKCS9_VIA_CRMF);

	seq->contents().push_back(oid);
	seq->contents().push_back(set);
	set->contents().push_back(inner);

	for ( std::size_t idx = 0; idx < m_vec.size(); idx++ )
		inner->contents().push_back(m_vec.at(idx));

	// this should equal 0xA0
	// (CONTEXT_SPECIFIC << 6|CONSTRUCTED << 5|0x00)
	m_set.tag(ASN1_CONTEXT_SPECIFIC_ZERO);
	m_set.tag_class(ASN1_CONTEXT_SPECIFIC_CLASS);
	m_set.encoding(ASN1_CONSTRUCTED);
	m_set.contents().push_back(seq);

	return m_set;
}

set_t&
x509_extensions_t::to_signing_set(void)
{
	sequence_t*	seq(new sequence_t);
	sequence_t* inner(new sequence_t);
	oid_t*		oid(new oid_t);
	set_t*		set(new set_t);

	m_set.get_data().clear();
	m_set.contents().clear();

	oid->set_oid(EXTENSION_REQUEST_PKCS9_VIA_CRMF);

	seq->contents().push_back(oid);
	seq->contents().push_back(set);
	set->contents().push_back(inner);

	for ( std::size_t idx = 0; idx < m_vec.size(); idx++ )
		inner->contents().push_back(m_vec.at(idx));

	m_set.contents().push_back(seq);

	return m_set;
}

x509_signature_t::x509_signature_t(pki_info_t& pki) : m_pki(pki) 
{ 
	return;
}

x509_signature_t::~x509_signature_t(void) 
{ 
	return;
}

const std::string& 
x509_signature_t::data(void) const 
{ 
	return m_str; 
}

void 
x509_signature_t::data(const std::string& v) 
{ 
	m_str = v; 
	return; 
}

bit_string_t
x509_signature_t::generate_signature(const std::string& v) const
{
	std::vector< uint8_t >	output;
	bit_string_t			bit;

	m_pki.sha256_rsa_sign(v, output);

	if ( 0 != ( output.size() % 8 ) )
		throw std::runtime_error("Unhandled edge case encountered due to remainder bits in bit_string_t input");

	bit.remainder_bits(0x00);

	for ( auto& byte : output )
		bit.get_data().push_back(byte);

	return bit;
}

std::string
x509_signature_t::to_string(void) const
{
	return generate_signature(m_str).to_string();
}

bit_string_t
x509_signature_t::to_bit_string(void) const
{
	return generate_signature(m_str);
}

x509_request_t::x509_request_t(void) : m_signature(m_csr_info.pki_info()) 
{ 
	return;
}

x509_request_t::~x509_request_t(void) 
{ 
	return;
}

certificate_request_info_t& 
x509_request_t::csr_info(void) 
{ 
	return m_csr_info; 
}

algorithm_identifier_t& 
x509_request_t::algorithm_indentifier(void) 
{ 
	return m_algorithm; 
}

x509_signature_t& 
x509_request_t::signature(void) 
{ 
	return m_signature; 
}

std::string 
x509_request_t::to_string(void)
{
	std::string ret("");
	sequence_t	seq;

	seq.contents().push_back(new sequence_t(m_csr_info.to_sequence()));
	seq.contents().push_back(new sequence_t(m_algorithm.to_sequence()));

	ret = m_csr_info.to_string();
	m_signature.data(ret);

	seq.contents().push_back(new bit_string_t(m_signature.to_bit_string()));
	ret = seq.to_string();
	return ret;
}