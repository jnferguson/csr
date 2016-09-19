#pragma once

#include <cstdint>
#include <cstdarg>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>

#include "asnone.hpp"
#include "rsa.hpp"

typedef enum
{
	RFC4524_USERID = 0,	RFC4524_INFO, RFC4524_DOMAIN_COMPONENT, RFC2985_EMAIL_ADDRESS, RFC2985_UNSTRUCTUREDNAME, 
	RFC2985_UNSTRUCTUREDADDRESS, EV_JURISDICTIONOFINCORPORATIONLOCALITYNAME, EV_JURISDICTIONOFINCORPORATIONSTATEORPROVINCENAME,
	EV_JURISDICTIONOFINCORPORATIONCOUNTRYNAME, X520_COMMONNAME, X520_SURNAME, X520_SERIALNUMBER, X520_COUNTRYNAME, X520_LOCALITYNAME, 
	X520_STATEORPROVINCENAME, X520_STREETADDRESS, X520_ORGANIZATIONNAME, X520_ORGANIZATIONUNIT, X520_TITLE, X520_DESCRIPTION, 
	X520_BUSINESSCATEGORY, X520_POSTALADDRESS, X520_POSTALCODE, X520_POSTOFFICEBOX, X520_TELEPHONENUMBER, X520_NAME, X520_GIVENNAME,
	X520_INITIALS, X520_UNIQUEIDENTIFIER, X520_DISTINGUISHEDQUALIFER, X520_HOUSEIDENTIFIER, X520_DIRECTORYMANAGEMENTDOMAINNAME,
	DN_ATTRIBUTES_INVALID_VALUE
} DN_ATTRIBUTES_T;

static constexpr std::pair< DN_ATTRIBUTES_T, const char* > g_dn_attributes[] =
{
	{ RFC4524_USERID,										"0.9.2342.19200300.100.1.1" },
	{ RFC4524_INFO,											"0.9.2342.19200300.100.1.4" },
	{ RFC4524_DOMAIN_COMPONENT,								"0.9.2342.19200300.100.1.25" },
	{ RFC2985_EMAIL_ADDRESS,								"1.2.840.113549.1.9.1" },
	{ RFC2985_UNSTRUCTUREDNAME,								"1.2.840.113549.1.9.2" },
	{ RFC2985_UNSTRUCTUREDADDRESS,							"1.2.840.113549.1.9.8" },
	{ EV_JURISDICTIONOFINCORPORATIONLOCALITYNAME,			"1.3.6.1.4.1.311.60.2.1.1" },
	{ EV_JURISDICTIONOFINCORPORATIONSTATEORPROVINCENAME,	"1.3.6.1.4.1.311.60.2.1.2" },
	{ EV_JURISDICTIONOFINCORPORATIONCOUNTRYNAME,			"1.3.6.1.4.1.311.60.2.1.3" },
	{ X520_COMMONNAME,										"2.5.4.3" },
	{ X520_SURNAME,											"2.5.4.4" },
	{ X520_SERIALNUMBER,									"2.5.4.5" },
	{ X520_COUNTRYNAME,										"2.5.4.6" },
	{ X520_LOCALITYNAME,									"2.5.4.7" },
	{ X520_STATEORPROVINCENAME,								"2.5.4.8" },
	{ X520_STREETADDRESS,									"2.5.4.9" },
	{ X520_ORGANIZATIONNAME,								"2.5.4.10" },
	{ X520_ORGANIZATIONUNIT,								"2.5.4.11" },
	{ X520_TITLE,											"2.5.4.12" }, 
	{ X520_DESCRIPTION,										"2.5.4.13" },
	{ X520_BUSINESSCATEGORY,								"2.5.4.15" },
	{ X520_POSTALADDRESS,									"2.5.4.16" },
	{ X520_POSTALCODE,										"2.5.4.17" },
	{ X520_POSTOFFICEBOX,									"2.5.4.18" },	
	{ X520_TELEPHONENUMBER,									"2.5.4.20" },
	{ X520_NAME,											"2.5.4.41" },
	{ X520_GIVENNAME,										"2.5.4.42" },
	{ X520_INITIALS,										"2.5.4.43" },
	{ X520_UNIQUEIDENTIFIER,								"2.5.4.45" },
	{ X520_DISTINGUISHEDQUALIFER,							"2.5.4.46" },
	{ X520_HOUSEIDENTIFIER,									"2.5.4.51" },
	{ X520_DIRECTORYMANAGEMENTDOMAINNAME,					"2.5.4.54" }
};

class distinguished_name_t : public tlv_t
{
	private:
	protected:
		oid_t			m_oid;
		std::string		m_name;
	public:

		distinguished_name_t(const DN_ATTRIBUTES_T&, const std::string&);
		virtual ~distinguished_name_t(void);
		
		virtual std::string name(void);
		virtual void name(const std::string& );
		
		virtual set_t to_set(void);
		virtual std::string to_string(void);

};

class dn_common_name_t final : public distinguished_name_t
{
	private:
	protected:
	public:
		dn_common_name_t(void);
		dn_common_name_t(const std::string&);
		dn_common_name_t(const char*);
		
		virtual ~dn_common_name_t(void) final;

		virtual std::string& common_name(void) final;
		virtual void common_name(const std::string& v) final;
};

class dn_country_name_t final : public distinguished_name_t
{
	private:
	protected:
	public:
		dn_country_name_t(void);
		dn_country_name_t(const std::string&);
		dn_country_name_t(const char*);
		virtual ~dn_country_name_t(void) final;
		
		virtual std::string& country_name(void) final;
		virtual void country_name(const std::string& v) final;
};

class dn_locality_name_t final : public distinguished_name_t
{
	private:
	protected:
	public:
	dn_locality_name_t(void);
	dn_locality_name_t(const std::string&);
	dn_locality_name_t(const char*);

	virtual ~dn_locality_name_t(void) final;

	virtual std::string& locality_name(void) final;
	virtual void locality_name(const std::string&) final;
};

class dn_organization_name_t final : public distinguished_name_t
{
	private:
	protected:
	public:
		dn_organization_name_t(void);
		dn_organization_name_t(const std::string&);
		dn_organization_name_t(const char*);

		virtual	~dn_organization_name_t(void) final;

		virtual std::string& organization_name(void) final;
		virtual void organization_name(const std::string&) final;
};

class dn_state_or_province_name_t final : public distinguished_name_t
{
	private:
	protected:
	public:
		dn_state_or_province_name_t(void);
		dn_state_or_province_name_t(const std::string&);
		dn_state_or_province_name_t(const char*);
		
		virtual ~dn_state_or_province_name_t(void) final;

		virtual std::string& state_or_province_name(void) final;
		virtual void state_or_province_name(const std::string&) final;
};

class dn_organizational_unit_name_t final : public distinguished_name_t
{
	private:
	protected:
	public:
		dn_organizational_unit_name_t(void);
		dn_organizational_unit_name_t(const std::string& n);
		dn_organizational_unit_name_t(const char* n);
	
		virtual ~dn_organizational_unit_name_t(void) final;

		virtual std::string& organizational_unit_name(void) final;
		virtual void organizational_unit_name(const std::string& v) final;
};


// The RSA usage in this class is insecure and not intended to
// be used in any cryptographic operations of importance; its
// specifically utilized to generate a CSR and nothing more.
//
// In other words, if you should feel inclined to copy/paste
// this class or similar, don't-- at the very least storing
// the keys in "insecure" memory that is not wiped is asking
// for a key leak.
//
// I don't actually think the two things will ever confuse
// anyone, but it costs nothing to leave a note in the
// comments just in case.

class pki_info_t
{
	private:
	protected:
		rsa_t			m_rsa;
		std::string		m_modulus;
		std::string		m_public_exponent;

	public:
	pki_info_t(const std::size_t siz = 2048);

	~pki_info_t(void);

	std::string to_string(void);
	sequence_t* to_sequence(void);
	bool sha256_rsa_sign(const std::string&, std::vector< uint8_t >&);

};

class algorithm_identifier_t
{
	private:
	protected:
	public:
		algorithm_identifier_t(void);
		~algorithm_identifier_t(void);

		std::string to_string(void);
		sequence_t to_sequence(void);
};

class extension_t
{
	private:
	protected:
	oid_t			m_oid;
	octet_string_t	m_oct;

	public:
	extension_t(void);
	extension_t(const std::string& oid = std::string(""));
	virtual ~extension_t(void);

	virtual oid_t& oid(void);

	virtual void oid(const std::string&);
	virtual octet_string_t& octet_string(void);

	virtual std::string to_string(void) = 0;
	virtual sequence_t to_sequence(void) = 0;
};

/*
*
*	basicConstraints EXTENSION ::= {
*	   SYNTAX         BasicConstraintsSyntax
*	   CRITICAL       TRUE
*	   IDENTIFIED BY id-ce-basicConstraints
*	}
*
*	BasicConstraintsSyntax ::= SEQUENCE {
*	   cA                 BOOLEAN  DEFAULT FALSE,
*	   pathLenConstraint  INTEGER (0..MAX)  OPTIONAL
*	}
*/
class basic_constraints_t final : public extension_t
{
	private:
	protected:
	bool			m_ca;
	std::size_t		m_length;

	public:
	basic_constraints_t(void);
	virtual ~basic_constraints_t(void);

	virtual bool ca(void) const;
	virtual void ca(const bool);

	virtual std::size_t path_length(void) const;
	virtual void path_length(const std::size_t);

	virtual std::string to_string(void);
	virtual sequence_t to_sequence(void);
};

/*
*	keyUsage EXTENSION ::= {
*		SYNTAX         KeyUsage
*		CRITICAL       TRUE
*		IDENTIFIED BY id-ce-keyUsage
*	}
*
*	KeyUsage ::= BIT STRING {
*		digitalSignature  (0),
*		nonRepudiation    (1),
*		keyEncipherment   (2),
*		dataEncipherment  (3),
*		keyAgreement      (4),
*		keyCertSign       (5),             -- For use in CA-certificates only
*		cRLSign           (6)              -- For use in CA-certificates only
*	}
*/
class key_usage_t final : public extension_t
{
	private:
	protected:
	bool	m_signature;
	bool	m_nonrepudiation;
	bool	m_key_encipherment;
	bool	m_data_encipherment;
	bool	m_key_agreement;
	bool	m_key_cert_sign;
	bool	m_crl_sign;

	public:
	key_usage_t(void);

	virtual ~key_usage_t(void);

	virtual bool signature(void) const;
	virtual void signature(const bool);

	virtual bool nonrepudiation(void) const;
	virtual void nonrepudiation(const bool);

	virtual bool key_encipherment(void) const;
	virtual void key_encipherment(const bool);

	virtual bool data_encipherment(void) const;
	virtual void data_encipherment(const bool);

	virtual bool key_agreement(void) const;
	virtual void key_agreement(const bool);

	virtual bool key_cert_sign(void) const;
	virtual void key_cert_sign(const bool);

	virtual bool crl_sign(void) const;
	virtual void crl_sign(const bool);

	virtual std::string to_string(void);
	virtual sequence_t to_sequence(void);
};

// *	dNSName		[2] IA5String,
class dns_name_t final : public tlv_t
{
	private:
	protected:
	public:
	dns_name_t(void);
	virtual ~dns_name_t(void) final;

	virtual void add_name(const std::string&);
	virtual void add_name(const char*, std::size_t);
};

//	IPAddress	[7] OCTET STRING 
class ip_address_t final : public tlv_t
{
	private:
	protected:
	public:
	ip_address_t(void);

	virtual ~ip_address_t(void);

	virtual void append(const uint8_t);
	virtual void append(const uint16_t);
	virtual void append(const uint32_t);
	virtual void append(const uint64_t);
	virtual void append(const std::vector< uint8_t >&);

};

/*
*	subjectAltName EXTENSION ::= {
*	SYNTAX GeneralNames
*	IDENTIFIED BY id-ce-subjectAltName
*	}
*
*	GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
*
*	GeneralName ::= CHOICE {
*	otherName	[0] INSTANCE OF OTHER-NAME,
*	rfc822Name	[1] IA5String,
*	dNSName		[2] IA5String,
*	x400Address	[3] ORAddress,
*	directoryName	[4] Name,
*	ediPartyName	[5] EDIPartyName,
*	uniformResourceIdentifier [6] IA5String,
*	IPAddress	[7] OCTET STRING,
*	registeredID	[8] OBJECT IDENTIFIER
*	}
*
*	OTHER-NAME ::= TYPE-IDENTIFIER
*
*	EDIPartyName ::= SEQUENCE {
*	nameAssigner [0] DirectoryString {ub-name} OPTIONAL,
*	partyName [1] DirectoryString {ub-name}
*	}
*	}
*/
class subject_altname_t final : public extension_t
{
	private:
	protected:
	std::vector< tlv_t* >	m_contents;

	public:
	subject_altname_t(void);
	virtual ~subject_altname_t(void) final;

	virtual std::vector< tlv_t* >& contents(void);
	virtual std::string to_string(void);
	virtual sequence_t to_sequence(void);
};

class x509_extensions_t
{
	private:
	set_t						m_set;
	std::vector< sequence_t* >	m_vec;

	protected:
	public:
	x509_extensions_t(void);
	~x509_extensions_t(void);

	std::string to_signing_string(void);
	std::string to_string(void);
	set_t& to_set(void);
	set_t& to_signing_set(void);

	void add_extension(sequence_t&);

};

class certificate_request_info_t
{
	private:
		integer_t							m_version;
		std::vector< distinguished_name_t >	m_subject;
		pki_info_t							m_pki_info;
		x509_extensions_t					m_extensions;

	protected:
	public:
		certificate_request_info_t(void);
		~certificate_request_info_t(void);

		integer_t& version(void);
		void version(const uint8_t& v);

		void add_subject_info(distinguished_name_t& v);
		std::vector< distinguished_name_t >& subject(void);

		pki_info_t& pki_info(void);

		x509_extensions_t& extensions(void);
		void add_extension(extension_t&);

		std::string to_string(void);
		std::string to_signing_string(void);

		sequence_t to_sequence(void);
};

class x509_signature_t
{
	private:
	protected:
		pki_info_t&	m_pki;
		std::string m_str;

	public:
		x509_signature_t(pki_info_t&);
		~x509_signature_t(void);

		const std::string& data(void) const;
		void data(const std::string&);

		bit_string_t generate_signature(const std::string& v) const;

		std::string to_string(void) const;

		bit_string_t to_bit_string(void) const;
};

class x509_request_t
{
	private:
		certificate_request_info_t	m_csr_info;
		algorithm_identifier_t		m_algorithm;
		x509_signature_t			m_signature;

	protected:
	public:
		x509_request_t(void);
		~x509_request_t(void);

		certificate_request_info_t& csr_info(void);
		algorithm_identifier_t& algorithm_indentifier(void);
		x509_signature_t& signature(void);

		std::string to_string(void);
};

