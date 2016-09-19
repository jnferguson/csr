#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <limits>
#include <vector>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>
#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

class rsa_t
{
	private:
	protected:
		std::size_t						m_ksize;
		BCRYPT_ALG_HANDLE				m_algorithm;
		BCRYPT_KEY_HANDLE				m_key;
		BCRYPT_RSAKEY_BLOB*				m_kblob;
		std::string						m_public_exponent;
		std::string						m_modulus;

		bool extract_blob(void);

	public:
		rsa_t(std::size_t siz = 2048);
		~rsa_t(void);

		bool sha256(const std::string&, std::vector< uint8_t >&);
		bool sign(const std::string&, std::vector< uint8_t >&);
		bool verify(const std::string&, const std::string&, const std::string&);

		void size(const std::size_t siz);

		std::string public_modulus(void);
		std::string public_exponent(void);

};

