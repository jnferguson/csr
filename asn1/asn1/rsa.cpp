#include "rsa.hpp"

bool
rsa_t::extract_blob(void)
{
	uint8_t*	start(nullptr);
	uint8_t*	end(nullptr);
	uint8_t*	current(nullptr);
	std::size_t	len(0);

	if ( BCRYPT_RSAPUBLIC_MAGIC != m_kblob->Magic )
		return false;


	current = reinterpret_cast< uint8_t* >( m_kblob );
	current += sizeof(BCRYPT_RSAKEY_BLOB);

	len = m_kblob->cbPublicExp;
	m_public_exponent = "";

	//m_public_exponent.resize(len);
	//std::memcpy(&m_public_exponent[ 0 ], current, len);
	//current += len;

	for ( start = current, end = start + len; current < end; current++ )
		m_public_exponent += *current;

	len = m_kblob->cbModulus;
	m_modulus = "";

	for ( start = current, end = start + len; current < end; current++ )
		m_modulus += *current;


	return true;
}

rsa_t::rsa_t(std::size_t siz) : m_ksize(siz)
{
	ULONG		len(0);
	uint8_t*	blob(nullptr);
	NTSTATUS	ret = ::BCryptOpenAlgorithmProvider(&m_algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);

	if ( STATUS_SUCCESS != ret )
		throw std::runtime_error("Error in ::BCryptOpenAlgorithmProvider()");

	if ( ( std::numeric_limits< ULONG >::max )( ) < m_ksize ) {
		::BCryptCloseAlgorithmProvider(m_algorithm, 0);
		throw std::invalid_argument("rsa_t::rsa_t(): Invalid/overly large keysize");
	}
	ret = ::BCryptGenerateKeyPair(m_algorithm, &m_key, m_ksize, 0);

	if ( STATUS_SUCCESS != ret ) {
		::BCryptCloseAlgorithmProvider(m_algorithm, 0);
		throw std::runtime_error("Error in ::BCryptGenerateKeyPair()");
	}

	ret = ::BCryptFinalizeKeyPair(m_key, 0);

	if ( STATUS_SUCCESS != ret ) {
		::BCryptDestroyKey(m_key);
		::BCryptCloseAlgorithmProvider(m_algorithm, 0);
		throw std::runtime_error("Error in ::BCryptFinalizeKeyPair()");
	}

	ret = ::BCryptExportKey(m_key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &len, 0);

	if ( STATUS_SUCCESS != ret ) {
		::BCryptDestroyKey(m_key);
		::BCryptCloseAlgorithmProvider(m_algorithm, 0);
		throw std::runtime_error("Error in ::BCryptExportKey()");
	}

	blob = new uint8_t[ len ];

	ret = ::BCryptExportKey(m_key, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob, len, &len, 0);

	if ( STATUS_SUCCESS != ret ) {
		::BCryptDestroyKey(m_key);
		::BCryptCloseAlgorithmProvider(m_algorithm, 0);
		throw std::runtime_error("Error in ::BCryptExportKey()");
	}

	m_kblob = reinterpret_cast< BCRYPT_RSAKEY_BLOB* >( blob );

	if ( false == extract_blob() )
		throw std::runtime_error("Error while extracting key blob");

	return;
}

rsa_t::~rsa_t(void)
{
	uint8_t* ptr(reinterpret_cast< uint8_t* >( m_kblob ));

	::BCryptDestroyKey(m_key);
	::BCryptCloseAlgorithmProvider(m_algorithm, 0);
	delete[] ptr;
	m_kblob = nullptr;
	return;
}

bool
rsa_t::sha256(const std::string& v, std::vector< uint8_t >& out)
{
	BCRYPT_ALG_HANDLE		algorithm(nullptr);
	BCRYPT_HASH_HANDLE		hash_hnd(nullptr);
	NTSTATUS				status(STATUS_UNSUCCESSFUL);
	ULONG					data(0), hash_size(0), hashobj_size(0);
	PBYTE					hashobj(nullptr), hash(nullptr), value(nullptr);

	if ( !NT_SUCCESS(status = ::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
		return false;
	}

	if ( !NT_SUCCESS(status = ::BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, 
					reinterpret_cast< PBYTE >(&hashobj_size), sizeof(ULONG), &data, 0)) ) {
		::BCryptCloseAlgorithmProvider(algorithm, 0);
		return false;

	}

	hashobj = new BYTE[ hashobj_size ];
	std::memset(hashobj, 0, hashobj_size);

	if ( !NT_SUCCESS(status = ::BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
												  reinterpret_cast<PBYTE>( &hash_size ), sizeof(ULONG), &data, 0)) ) {
		delete hashobj;
		::BCryptCloseAlgorithmProvider(algorithm, 0);
		return false;
	}

	hash = new BYTE[ hash_size ];
	std::memset(hash, 0, hash_size);

	if ( !NT_SUCCESS(status = ::BCryptCreateHash(algorithm, &hash_hnd, hashobj, hashobj_size, nullptr, 0, 0)) ) {
		delete hash;
		delete hashobj;
		::BCryptCloseAlgorithmProvider(algorithm, 0);
		return false;
	}

	value = new UCHAR[ v.length() ];
	std::memcpy(value, v.data(), v.length());

	if ( !NT_SUCCESS(status = ::BCryptHashData(hash_hnd, value, v.length(), 0)) ) {
		delete hash;
		delete hashobj;
		delete value;
		::BCryptDestroyHash(hash_hnd);
		::BCryptCloseAlgorithmProvider(algorithm, 0);
		return false;
	}

	if (!NT_SUCCESS(status = ::BCryptFinishHash(hash_hnd, hash, hash_size, 0))) {
		delete hash;
		delete hashobj;
		delete value;
		::BCryptDestroyHash(hash_hnd);
		::BCryptCloseAlgorithmProvider(algorithm, 0);
		return false;
	}

	out.resize(hash_size);
	std::memcpy(&out[ 0 ], hash, out.size());

	delete hash;
	delete hashobj;
	delete value;
	::BCryptDestroyHash(hash_hnd);
	::BCryptCloseAlgorithmProvider(algorithm, 0);
	return true;

}

bool 
rsa_t::sign(const std::string& v, std::vector< uint8_t >& out)
{
	BCRYPT_PKCS1_PADDING_INFO	pad = { 0 };
	std::vector< uint8_t >		hash;
	ULONG						len(0);
	NTSTATUS					status(STATUS_UNSUCCESSFUL);

	out.clear();

	if ( false == sha256(v, hash) ) 
		return false;

	pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;

	if ( !NT_SUCCESS(status = ::BCryptSignHash(m_key, &pad, hash.data(), hash.size(), nullptr, 0, &len, BCRYPT_PAD_PKCS1)) ) 
		return false;

	out.resize(len);
	std::memset(out.data(), 0, out.size());

	if ( !NT_SUCCESS(status = ::BCryptSignHash(m_key, &pad, hash.data(), hash.size(), out.data(), out.size(), &len, BCRYPT_PAD_PKCS1)) )
		return false;


	return true;

}

bool 
rsa_t::verify(const std::string& key, const std::string& data, const std::string& signature)
{
	CERT_CONTEXT*				ctx(nullptr);
	CERT_INFO*					inf(nullptr);
	CERT_PUBLIC_KEY_INFO*		kin(nullptr);
	BCRYPT_KEY_HANDLE			hnd(INVALID_HANDLE_VALUE);
	BCRYPT_PKCS1_PADDING_INFO	pad = { 0 };
	std::vector< uint8_t >		hash;
	NTSTATUS					status(STATUS_UNSUCCESSFUL);

	ctx = (CERT_CONTEXT*)::CertCreateContext(CERT_STORE_CERTIFICATE_CONTEXT, X509_ASN_ENCODING, 
											(const BYTE*)key.data(), key.size(), 0, nullptr);

	if ( nullptr == ctx )
		return false;

	inf = ctx->pCertInfo;
	kin = &inf->SubjectPublicKeyInfo;

	if ( !::CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, kin, 0, nullptr, &hnd) )
		return false;

	if ( false == sha256(data, hash) )
		return false;

	pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;

	if ( !NT_SUCCESS(status = ::BCryptVerifySignature(hnd, &pad, hash.data(), hash.size(), (PUCHAR)signature.data(), signature.size(), BCRYPT_PAD_PKCS1)) ) {
		if ( STATUS_INVALID_SIGNATURE == status )
			return false;

		throw std::runtime_error("");
	}

	return true;

}

void
rsa_t::size(const std::size_t siz)
{
	/*CryptoPP::RSA::PrivateKey	priv;
	CryptoPP::RSA::PublicKey	pub;


	if ( std::numeric_limits< unsigned int >::max() < siz )
	throw std::invalid_argument("rsa_t::rsa_t(): Invalid/overly large keysize");

	priv.GenerateRandomWithKeySize(m_rng, static_cast< unsigned int >(siz));
	pub.Initialize(priv.GetModulus(), priv.GetPublicExponent());

	m_private	= priv;
	m_public	= pub;
	m_ksize		= siz;

	if ( false == m_private.Validate(m_rng, 3) )
	throw std::runtime_error("rsa_t::rsa_t(): Generated RSA private key is invalid.");

	if ( false == m_public.Validate(m_rng, 3) )
	throw std::runtime_error("rsa_t::rsa_t(): Generated RSA public key is invalid.");*/

	return;

}

std::string
rsa_t::public_modulus(void)
{
	return m_modulus; // ""; // CryptoPP::IntToString< CryptoPP::Integer >(m_public.GetModulus());
}

std::string
rsa_t::public_exponent(void)
{
	return m_public_exponent; // ""; // CryptoPP::IntToString< CryptoPP::Integer >(m_public.GetPublicExponent());
}
