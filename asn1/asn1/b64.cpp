#include "b64.hpp"

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";


std::string
base64_encode(const std::vector< uint8_t >& data)
{
	std::string					ret("");
	std::size_t					i(0);
	std::array< uint8_t, 3 >	art;
	std::array< uint8_t, 4 >	arf;

	for ( const auto& byte : data ) {
		art[ i++ ] = byte;

		if ( 3 == i ) {
			arf[ 0 ] = ( art[ 0 ] & 0xfc ) >> 2;
			arf[ 1 ] = ( ( art[ 0 ] & 0x03 ) << 4 ) + ( ( art[ 1 ] & 0xf0 ) >> 4 );
			arf[ 2 ] = ( ( art[ 1 ] & 0x0f ) << 2 ) + ( ( art[ 2 ] & 0xc0 ) >> 6 );
			arf[ 3 ] = art[ 2 ] & 0x3f;

			for ( i = 0; i < 4; i++ )
				ret += base64_chars[ arf[ i ] ];

			i = 0;
		}
	}

	if ( 0 != i ) {
		for ( std::size_t j = i; j < 3; j++ )
			art[ j ] = '\0';

		arf[ 0 ] = ( art[ 0 ] & 0xfc ) >> 2;
		arf[ 1 ] = ( ( art[ 0 ] & 0x03 ) << 4 ) + ( ( art[ 1 ] & 0xf0 ) >> 4 );
		arf[ 2 ] = ( ( art[ 1 ] & 0x0f ) << 2 ) + ( ( art[ 2 ] & 0xc0 ) >> 6 );
		arf[ 3 ] = art[ 2 ] & 0x3f;

		for ( std::size_t j = 0; j < i + 1; j++ ) // its not possible for i to be > 3
			ret += base64_chars[ arf[ j ] ];

		while ( 3 > i++ )
			ret += '=';
	}

	return ret;
}

std::string 
base64_encode(const std::string& data)
{
	std::string					ret("");
	std::size_t					i(0);
	std::array< uint8_t, 3 >	art;
	std::array< uint8_t, 4 >	arf;

	for ( const auto& byte : data ) {
		art[ i++ ] = byte;

		if ( 3 == i ) {
			arf[ 0 ] = ( art[ 0 ] & 0xfc ) >> 2;
			arf[ 1 ] = ( ( art[ 0 ] & 0x03 ) << 4 ) + ( ( art[ 1 ] & 0xf0 ) >> 4 );
			arf[ 2 ] = ( ( art[ 1 ] & 0x0f ) << 2 ) + ( ( art[ 2 ] & 0xc0 ) >> 6 );
			arf[ 3 ] = art[ 2 ] & 0x3f;

			for ( i = 0; i < 4; i++ )
				ret += base64_chars[ arf[ i ] ];

			i = 0;
		}
	}

	if ( 0 != i ) {
		for ( std::size_t j = i; j < 3; j++ )
			art[ j ] = '\0';

		arf[ 0 ] = ( art[ 0 ] & 0xfc ) >> 2;
		arf[ 1 ] = ( ( art[ 0 ] & 0x03 ) << 4 ) + ( ( art[ 1 ] & 0xf0 ) >> 4 );
		arf[ 2 ] = ( ( art[ 1 ] & 0x0f ) << 2 ) + ( ( art[ 2 ] & 0xc0 ) >> 6 );
		arf[ 3 ] = art[ 2 ] & 0x3f;

		for ( std::size_t j = 0; j < i + 1; j++ ) // its not possible for i to be > 3
			ret += base64_chars[ arf[ j ] ];

		while ( 3 > i++ )
			ret += '=';
	}

	return ret;
}