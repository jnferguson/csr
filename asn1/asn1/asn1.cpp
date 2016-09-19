// asn1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "x509_request.hpp"
#include "hexdump.hpp"
#include "b64.hpp"

#include <iostream>
#include <array>

struct distinguished_set_t
{
	dn_country_name_t				cc;
	dn_state_or_province_name_t		state;
	dn_locality_name_t				locality;
	dn_organizational_unit_name_t	org;
	dn_common_name_t				cn;

	distinguished_set_t(const char* c = "US",
						const char* s = "MN",
						const char* l = "Minneapolis",
						const char* o = "Domain Control Validated",
						const char* n = "test_csr") : cc(c), state(s), locality(l), org(o), cn(n)
	{
		return;
	}
};

struct extensions_set_t
{
	basic_constraints_t		bas;
	key_usage_t				key;
	dns_name_t				dns[ 3 ];
	ip_address_t			ips[ 2 ];
	subject_altname_t		alt;

	extensions_set_t(void)
	{
		bas.ca(false);
		bas.path_length(0);
		key.data_encipherment(false);
		key.key_agreement(false);
		key.key_cert_sign(false);
		key.crl_sign(false);


		dns[ 0 ].add_name("kb.example.com");
		dns[ 1 ].add_name("helpdesk.example.org");
		dns[ 2 ].add_name("systems.example.net");
		ips[ 0 ].append(static_cast< uint32_t >( 0xC0A80101 ));
		ips[ 1 ].append(static_cast< uint32_t >( 0xC0A8450E ));
		alt.contents().push_back(&dns[ 0 ]);
		alt.contents().push_back(&dns[ 1 ]);
		alt.contents().push_back(&dns[ 2 ]);
		alt.contents().push_back(&ips[ 0 ]);
		alt.contents().push_back(&ips[ 1 ]);
	}
};

signed int
main(void)
{
	distinguished_set_t		dn("US", "MN", "Minneapolis", "Domain Control Validated", "test_csr");
	extensions_set_t		es;
	x509_request_t			csr;
	hexdump_t				hex;

	csr.csr_info().add_subject_info(dn.cc);
	csr.csr_info().add_subject_info(dn.state);
	csr.csr_info().add_subject_info(dn.locality);
	csr.csr_info().add_subject_info(dn.org);
	csr.csr_info().add_subject_info(dn.cn);



	//csr.csr_info().add_extension(es.bas);
	//csr.csr_info().add_extension(es.key);
	csr.csr_info().add_extension(es.alt);

	csr.csr_info().version(0x00);

	std::cout << "-----BEGIN CERTIFICATE REQUEST-----" << std::endl << std::endl;
	std::cout << base64_encode(csr.to_string()) << std::endl;
	// OpenSSLs PEM reading routines are flakey, if the last line
	// is not 65 bytes long, then we cannot have a blank line by itself.
	// I haven't tested all of the edges cases, what I needed to do was accomplished
	// and whether the library breaks when a new line is absent was not tested.
	std::cout << "-----END CERTIFICATE REQUEST-----" << std::endl << std::endl;

	hex.set(csr.to_string());
	std::cout << hex.to_string() << std::endl;

	return 0;
}

