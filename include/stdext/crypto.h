#ifndef STDEXT_CRYPTO_H
#define STDEXT_CRYPTO_H

#include <memory>
#include <string>
#include <cstring>
#include <iostream>
#include <exception>
#include <array>
#include <utility>


namespace stdext
{

  template <size_t N, class T = char>
  class digest : public std::array<T, N>
  {
    public:
        typedef std::basic_string<T> string_type;

  public:
	digest() : std::array<T, N>{} { }

	digest(const digest &digest) : std::array<T, N>(digest) {	}

    digest(const string_type &s)
    {
	    static const T hex[] = "0123456789abcdef";

	    if (s.length() != (N << 1)) 
            throw std::range_error("digest: string too short/long");
			
	    for (size_t i = 0; i < N; i++)
		{
		    const T *c1 = strchr(hex, s[i*2]);
		    const T *c2 = strchr(hex, s[i*2+1]);
		    if (!c1 || !c2)
                throw std::out_of_range("digest: can't convert character");

		    (*this)[i]  = ((char)(c1 - hex)) << 4;
		    (*this)[i] |= ((char)(c2 - hex));
		}
    }

	string_type str() const
	{
	    static const unsigned char hex[] = "0123456789abcdef";
        string_type result;
	    
        for (size_t i = 0; i < N; i++)
		{
		    unsigned char c = static_cast<T>((*this)[i]);
		    result += hex[c >> 4];
		    result += hex[c & 0xf];
		}
        
        return std::move(result);
	}
  };


  template <size_t N, class T = char>
  std::basic_ostream<T> &operator << (std::basic_ostream<T> &os, const digest<N, T> &id)
  {
    return os << id.str();
  }

  template <size_t N, class T = char>
  std::basic_istream<T> &operator >> (std::basic_istream<T> &is, digest<N, T> &id)
  {
    try {
    	std::basic_string<T> str;
    	is >> str;
        id = stdext::digest<N, T>(str);
    }
    catch (std::range_error e) {
		is.setstate(std::ios::badbit);
    }
    catch (std::out_of_range e) {
		is.setstate(std::ios::badbit);
    }
	return is;
  }


  class sha1sum
  {
	class detail;
	detail *_impl;

  public:
	typedef digest<20> digest_type;

	sha1sum();
	~sha1sum();
	void update(const void *data, size_t size);
	digest_type finalize();
  }; 

  class sha256sum
  {
	class detail;
	detail *_impl;

  public:
	typedef digest<32> digest_type;

    sha256sum();
    ~sha256sum();
	void update(const void *data, size_t size);
	digest_type finalize();
  }; 

} // stdext

#endif // STDEXT_CRYPTO_H