#pragma once
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <string>
#include <iterator>

#define TAG_CLASS_MASK 0xC0
#define PRIM_CONS_MASK 0x20
#define TAG_TAG_MASK 0x1F
#define MORE_TAG_MASK 0x80
#define MORE_TAG_TAG_MASK 0x7F

#define ASN1_UNIVERSAL_CLASS 0x00 //(0x00 << 6)
#define ASN1_APPLICATION_CLASS 0x01 //(0x01 << 6)
#define ASN1_CONTEXT_SPECIFIC_CLASS 0x02 //(0x02 << 6)
#define ASN1_PRIVATE_CLASS 0x03 //(0x03 << 6)

#define ASN1_PRIMITIVE 0x00 //(0x00 << 5)
#define ASN1_CONSTRUCTED 0x01 //(0x01 << 5)

#define ASN1_LENGTH_FORM_MASK 0x80
#define ASN1_LENGTH_LENGTH_MASK 0x7F

#define ASN1_EOC_TYPE 0x00
#define ASN1_BOOLEAN 0x01
#define ASN1_INTEGER_TYPE 0x02
#define ASN1_BIT_STRING 0x03
#define ASN1_OCTET_STRING 0x04
#define ASN1_NULL 0x05
#define ASN1_OBJECT_IDENTIFIER 0x06
#define ASN1_UTF8_STRING 0x0C
#define ASN1_SEQUENCE 0x10
#define ASN1_SET 0x11
#define ASN1_PRINTABLE_STRING 0x13

#define RSA_ENCRYPTION_OID "1.2.840.113549.1.1.1"
#define SHA256_RSA_ENCRYPTION "1.2.840.113549.1.1.11"
#define EXTENSION_REQUEST_PKCS9_VIA_CRMF "1.2.840.113549.1.9.14"
#define EXTENSION_BASIC_CONSTRAINTS "2.5.29.19"
#define EXTENSION_KEY_USAGE "2.5.29.15"
#define EXTENSION_SUBJECT_ALTNAME "2.5.29.17"

#define ASN1_CONTEXT_SPECIFIC_ZERO 0x00
#define ASN1_CONTEXT_SPECIFIC_TWO 0x02
#define ASN1_CONTEXT_SPECIFIC_SEVEN 0x07

class tlv_t
{
	private:
	protected:
		uint8_t					m_class;
		uint8_t					m_encoding;
		uint8_t					m_tag;
		bool					m_indefinite;
		std::vector< uint8_t >	m_length;
		std::vector< uint8_t >	m_data;

	public:
		tlv_t(void);
		tlv_t(const uint8_t cla, const uint8_t enc, const uint8_t tag, const bool indef = false);

		virtual ~tlv_t(void);

		virtual uint8_t tag(void) const;
		virtual void tag(const uint8_t);

		virtual uint8_t tag_class(void) const;
		virtual void tag_class(const uint8_t v);

		virtual bool universal_class(void) const;
		virtual bool application_class(void) const;
		virtual bool context_specific_class(void) const;
		virtual bool private_class(void) const;

		virtual void encoding(const uint8_t);

		virtual bool primitive(void) const;
		virtual bool constructed(void) const;
		virtual void indefinite(const bool set = true);
		virtual void length(const std::size_t v, bool indef = false);

		virtual std::vector< uint8_t >& get_length(void);

		virtual std::vector< uint8_t >& get_data(void);

		virtual std::string to_string(void);
};

class boolean_t final : public tlv_t
{
	private:
	protected:
		bool	m_value;

	public:
		boolean_t(void);
		virtual ~boolean_t(void) final;

		virtual bool is_true(void);
		virtual bool is_false(void);
		virtual bool value(void);
		virtual void value(const bool v);

		virtual std::string to_string(void);
};

class eoc_t final : public tlv_t
{
	private:
	protected:
	public:
		eoc_t(void);	
		virtual ~eoc_t(void) final;
};

class integer_t final : public tlv_t
{
	private:
	protected:
	public:
		integer_t(void);
		virtual ~integer_t(void) final;

		virtual std::string to_string(void);
};

class bit_string_t final : public tlv_t
{
	private:
	protected:
		uint8_t	m_remainder;

	public:
		// constructed bit strings as described in 8.6.2.1 et seq in T-REC-X.690-200811
		bit_string_t(void);
		virtual ~bit_string_t(void) final;

		virtual std::size_t remainder_bits(void) const;
		virtual void remainder_bits(const std::size_t);

		virtual std::string to_string(void);
};

class octet_string_t final : public tlv_t
{
	private:
	protected:
	public:
		// The segmented usage of this class as documented in 8.7 et seq in T-REC-X.690-200811
		// is not supported here.
		octet_string_t(void);
		virtual ~octet_string_t(void);
};

class oid_t final : public tlv_t
{
	private:
	protected:
	std::vector< std::string > split(const char *str, char c = '.');

	public:
		oid_t(void);
		virtual ~oid_t(void) final;
		virtual bool set_oid(const std::string&);
};

class utf8_string_t final : public tlv_t
{
	private:
	protected:
	public:
		utf8_string_t(void);
		virtual ~utf8_string_t(void) final;
};

class printable_string_t final : public tlv_t
{
	private:
	protected:
	public:
		printable_string_t(void);

		virtual ~printable_string_t(void) final;
};

class null_t final : public tlv_t
{
	private:
	protected:
	public:
		null_t(void);
		virtual ~null_t(void) final;
};

class set_t final : public tlv_t
{
	private:
		std::vector< tlv_t* >	m_contents;
	protected:
	public:
		set_t(void);

		virtual ~set_t(void) final;

		virtual std::vector< tlv_t* >& contents(void) final;

		virtual std::string to_string(void);
};

class sequence_t final : public tlv_t
{
	private:
		std::vector< tlv_t* >	m_contents;
	protected:
	public:
		sequence_t(void);

		virtual ~sequence_t(void) final;

		virtual std::vector< tlv_t* >& contents(void) final;
		virtual std::string to_string(void);
};