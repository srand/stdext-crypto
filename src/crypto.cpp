/* COPYRIGHT-SRC-R1 *
**************************************************************************
* Copyright (C) 2015 Robert Andersson
* All rights reserved.
*
* This Software is furnished under a software license agreement and
* may be used only in accordance with the terms of such agreement.
* Any other use or reproduction is prohibited. No title to and
* ownership of the Software is hereby transferred.
*
* PROPRIETARY NOTICE
* This Software consists of confidential information.
* Trade secret law and copyright law protect this Software.
* The above notice of copyright on this Software does not indicate
* any actual or intended publication of such Software.
**************************************************************************
* COPYRIGHT-END */

#include <stdext/crypto.h>

#if defined(_WIN32) || defined(_WIN64)
#define USE_WINCRYPT
#else
#define USE_OPENSSL
#endif

#ifdef USE_WINCRYPT
#include <Windows.h>
#include <Wincrypt.h>
#endif
#ifdef USE_OPENSSL
#include <openssl/sha.h>
#endif 

namespace stdext
{

#ifdef USE_OPENSSL
  class sha1sum::detail
  {
	SHA_CTX _ctx;
	
  public:
	detail()
	{
	  SHA1_Init(&_ctx);
	}
	
	void update(const void *data, size_t len)
	{
	  SHA1_Update(&_ctx, data, len);
	}
    
	stdext::sha1sum::digest_type finalize()
	{
        stdext::sha1sum::digest_type digest;
	    SHA1_Final((unsigned char *)&digest[0], &_ctx);
        return std::move(digest);
	}
  };

  class sha256sum::detail
  {
	SHA256_CTX _ctx;
	
  public:
	detail()
	{
	  SHA256_Init(&_ctx);
	}
	
	void update(const void *data, size_t len)
	{
	  SHA256_Update(&_ctx, data, len);
	}
    
	stdext::sha256sum::digest_type finalize()
	{
        stdext::sha256sum::digest_type digest;
	    SHA256_Final((unsigned char *)&digest[0], &_ctx);
        return std::move(digest);
	}
  };
#endif // USE_OPENSSL

#ifdef USE_WINCRYPT
namespace detail {
	class hashsum
	{
		HCRYPTPROV _provider;
		HCRYPTHASH _hash;

	public:
		hashsum(DWORD provider, DWORD algo)
			: _provider(0)
			, _hash(0)
		{
			if (!CryptAcquireContext(
				&_provider,
				NULL,
				NULL,
				provider,
				0))
			{
				throw std::runtime_error("CryptAcquireContext failed");
			}
			
			CryptCreateHash(_provider, algo, 0, 0, &_hash);
		}

		~hashsum()
		{
			if (_hash)
				CryptDestroyHash(_hash);
			if (_provider)
				CryptReleaseContext(_provider, 0);
		}
	
		void update(const void *data, size_t len)
		{
			if (!CryptHashData(_hash, (const BYTE *)data, len, 0)) {
				throw std::runtime_error("CryptHashData failed");
			}
		}
    
		template <class T>
		T finalize()
		{
            T digest;
			DWORD len = sizeof(digest);
			if (!CryptGetHashParam(_hash, HP_HASHVAL, (BYTE *)&digest[0], &len, 0)) {
				throw std::runtime_error("CryptGetHashParam failed");
			}
            return digest;
		}
	};
}
	class sha1sum::detail : public stdext::detail::hashsum
	{
	public:
		detail() : hashsum(PROV_RSA_FULL, CALG_SHA) {}
        sha1sum::digest_type finalize() {
            return hashsum::finalize<typename sha1sum::digest_type>();
        }
	};

	class sha256sum::detail : public stdext::detail::hashsum
	{
	public:
		detail() : hashsum(PROV_RSA_AES, CALG_SHA_256) {}
        sha256sum::digest_type finalize() {
            return hashsum::finalize<typename sha256sum::digest_type>();
        }
	};

#endif // USE_WINCRYPT


  sha1sum::sha1sum()
  : _impl(new sha1sum::detail())
  {
  }

  sha1sum::~sha1sum()
  {
      delete _impl;
      _impl = 0;
  }
  
  void sha1sum::update(const void *data, size_t size)
  {
	_impl->update(data, size);
  }

  sha1sum::digest_type sha1sum::finalize()
  {
	return std::move(_impl->finalize());
  }
  
  sha256sum::sha256sum()
  : _impl(new sha256sum::detail())
  {
  }

  sha256sum::~sha256sum()
  {
      delete _impl;
      _impl = 0;
  }

  void sha256sum::update(const void *data, size_t size)
  {
	_impl->update(data, size);
  }

  sha256sum::digest_type sha256sum::finalize()
  {
	return std::move(_impl->finalize());
  }

} // stdext
