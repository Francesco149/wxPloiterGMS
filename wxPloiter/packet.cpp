/*
	Copyright 2014 Francesco "Franc[e]sco" Noferi (francesco149@gmail.com)

	This file is part of wxPloiter.

	wxPloiter is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	wxPloiter is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with wxPloiter. If not, see <http://www.gnu.org/licenses/>.
*/

#include "packet.hpp"

#include "utils.hpp"
#include "checksumhack.hpp"
#include <sstream>
#include <iomanip>
#include <boost/algorithm/string.hpp>

namespace maple
{
	// readexception
	readexception::readexception()
		: out_of_range("failed to read expected packet data")
	{
		CHECKSUM_HACK()
		// empty
	}

	// packet
	packet::packet()
	{
		CHECKSUM_HACK()
		// empty
	}

	packet::~packet()
	{
		CHECKSUM_HACK()
		// empty
	}

	packet::packet(const packet &other)
	{
		CHECKSUM_HACK()
		// resize and reallocate the data array
		// (reserve used in append() does not reallocate because each extra element
		// is allocated by back_inserter as the data gets copied)
		data.resize(other.data.size());

		// copy new data over the data array
		std::copy(other.data.begin(), other.data.end(), data.begin());
	}

	packet::packet(const byte *pdata, size_t cb)
	{
		CHECKSUM_HACK()
		data.resize(cb);
		std::copy(pdata, pdata + cb, data.begin());
	}

	packet::packet(const std::vector<byte> &data)
	{
		CHECKSUM_HACK()
		this->data.resize(data.size());
		std::copy(data.begin(), data.end(), this->data.begin());
	}

	size_t packet::size() const
	{
		CHECKSUM_HACK()
		return data.size();
	}

	void packet::clear()
	{
		CHECKSUM_HACK()
		data.clear();
	}

	byte *packet::raw()
	{
		CHECKSUM_HACK()
		return &data[0];
	}

	const byte *packet::raw() const
	{
		CHECKSUM_HACK()
		return &data[0];
	}

	packet::iterator packet::begin()
	{
		CHECKSUM_HACK()
		return data.begin();
	}

	packet::iterator packet::end()
	{
		CHECKSUM_HACK()
		return data.end();
	}

	packet::const_iterator packet::begin() const
	{
		CHECKSUM_HACK()
		return data.begin();
	}

	packet::const_iterator packet::end() const
	{
		CHECKSUM_HACK()
		return data.end();
	}

	std::string packet::tostring() const
	{
		CHECKSUM_HACK()
		std::stringstream ss;

		// stringstream flags for formatting
		// std::hex = hex number output
		// std::setfill('0') = zero fill number formatting
		// std::uppercase = uppercase hex letters
		ss << std::hex << std::setfill('0') << std::uppercase;

		boost_foreach(const byte &b, data)
			ss << std::setw(2) << static_cast<word>(b) << " ";
		// I have no idea why but the only way to make it
		// format it properly is casting it to a 4-byte int
		// setw(2) truncates it back to a 2-digit hex number
		// setw is not "sticky" so it must be set each time

		return ss.str();
	}

	void packet::append_data(std::string hexstring)
	{
		CHECKSUM_HACK()
		boost::shared_ptr<utils::random> rnd = utils::random::get();
		boost::erase_all(hexstring, " ");
		hexstring = boost::to_upper_copy(hexstring);

		// trucated nibble
		if (hexstring.length() % 2)
			throw std::invalid_argument("unexpected truncated nibble");

		for (size_t i = 0; i < hexstring.length(); i += 2)
		{
			word b = 0x0000;

			// copy current byte string
			std::string strbyte(hexstring.begin() + i, hexstring.begin() + i + 2);

			// random bytes
			if (strbyte.find('*') != std::string::npos)
			{
				word mask = 0x0000;

				// random left nibble
				if (strbyte[0] == '*')
					mask |= 0x00F0;

				// random right nibble
				if (strbyte[1] == '*')
					mask |= 0x000F;

				b = rnd->getbyte();
				b &= mask; 
			}
			else
			{
				// convert byte string to integer
				std::istringstream iss(strbyte);
				iss >> std::hex >> b;

				if (iss.fail())
					throw std::invalid_argument("not a valid hex string");
			}

			append<byte>(static_cast<byte>(b));
		}
	}

	void packet::append_data(const byte *pdata, size_t cb)
	{
		CHECKSUM_HACK()
		data.reserve(data.size() + cb);
		std::copy(pdata, pdata + cb, std::back_inserter(data));
	}

	void packet::append_data(const std::vector<byte> &data)
	{
		CHECKSUM_HACK()
		append_data(&data[0], data.size());
	}

	void packet::append_string(const char *pstr, word len)
	{
		CHECKSUM_HACK()
		append_buffer(reinterpret_cast<const byte*>(pstr), len);
	}

	void packet::append_string(const std::string &str)
	{
		CHECKSUM_HACK()
		append_string(str.c_str(), static_cast<word>(str.length()));
	}

    bool packet::append_string(const std::basic_ostream<char> &format)
    {
		CHECKSUM_HACK()
        // obtain the stream's streambuf and cast it back to stringbuf
        std::basic_streambuf<char> * const strbuf = format.rdbuf();

        if (strbuf && typeid(*strbuf) == typeid(std::stringbuf))
        {
            const std::string &str = dynamic_cast<std::stringbuf &>(*strbuf).str();
			append_string(str);
			return true;
        }

        return false;
    }

	void packet::append_buffer(const byte *pdata, word cb)
	{
		CHECKSUM_HACK()
		append<word>(cb);
		append_data(pdata, cb);
	}

	bool packet::append_buffer(const std::vector<byte> &data)
	{
		CHECKSUM_HACK()
		// we can't pack buffers with a size that is larger than 2 bytes
		if (data.size() > 0xFFFF)
			return false;

		append_buffer(&data[0], static_cast<word>(data.size()));
		return true;
	}

	void packet::read_data(byte *pdata, size_t cb, const_iterator &it) const
	{
		CHECKSUM_HACK()
		// reached end of packet
		if (it + cb - 1 >= data.end())
			throw readexception();

		std::copy(it, it + cb, pdata);

		it += cb;
	}

	void packet::read_data(std::vector<byte> &data, size_t cb, const_iterator &it) const
	{
		CHECKSUM_HACK()
		data.resize(cb);
		
		try
		{
			read_data(&data[0], cb, it);
		}
		catch (const readexception &/*e*/)
		{
			data.clear();
			throw;
		}
	}

	byte *packet::read_data_nullterminated(const_iterator &it, size_t *length) const
	{
		CHECKSUM_HACK()
		// TODO: refactor this to a shared array
		byte *rawdata = NULL;
		const_iterator findnull;

		// scan the packet for the next NULL byte
		for (findnull = it; findnull != data.end(); findnull++)
		{
			if (*findnull == 0x00)
				break;
		}

		if (findnull == data.end())
			throw readexception();

		// calculate buffer size and allocate it
		size_t buffersize = findnull - it;
		rawdata = new byte[buffersize];

		try
		{
			read_data(rawdata, buffersize, it);
		}
		catch (const readexception &/*e*/)
		{
			delete [] rawdata;
			rawdata = NULL;
			throw; // cool! hands the exception over to the caller
		}

		if (length)
			*length = buffersize;

		return rawdata;
	}

	void packet::read_data_nullterminated(std::vector<byte> &data, const_iterator &it) const
	{
		CHECKSUM_HACK()
		// reads the nullterminated buffer into rawdata, then copies it to the std vector
		// and deletes our temporary rawdata array
		size_t len;
		byte *rawdata = read_data_nullterminated(it, &len);

		// this will never happen I think, read_data_nullterminated
		// should throw as soon as there's an error but whatever
		if (!rawdata) // read_data_nullterminated failed
			throw readexception();

		data.resize(len);
		std::copy(rawdata, rawdata + len, &data[0]);
		delete [] rawdata;
	}

	char *packet::read_string(const_iterator &it, size_t *length) const
	{
		CHECKSUM_HACK()
		// TODO: refactor this to a shared array
		char *str = NULL;
		word len;

		// get string length (first 2 bytes)
		read<word>(&len, it);

		str = new char[len + 1]; // +1 for the zero termination
		assert(str != NULL);

		// read string data with the size we obtained
		try
		{
			read_data(reinterpret_cast<byte *>(str), len, it);
		}
		catch (const readexception &/*e*/)
		{
			delete [] str;
			str = NULL;
			throw;
		}

		// add null termination
		str[len] = 0x00;

		if (length)
			*length = len;

		return str;
	}

	void packet::read_string(std::string &str, const_iterator &it) const
	{
		CHECKSUM_HACK()
		// uses read_string to normally read a string into a char array
		// then copies it to the std::string and deletes the temp array
		char *rawstr = read_string(it);

		if (!rawstr)
			throw readexception();

		str = rawstr;
		delete [] rawstr;
	}

	byte *packet::read_buffer(const_iterator &it, size_t *length) const
	{
		CHECKSUM_HACK()
		// TODO: refactor this to a shared array
		byte *buffer = NULL;
		word len;

		// get buffer length (first 2 bytes)
		read<word>(&len, it);

		buffer = new byte[len];
		assert(buffer != NULL);

		// read buffer data with the length we obtained
		try
		{
			read_data(buffer, len, it);
		}
		catch (const readexception &/*e*/)
		{
			delete [] buffer;
			buffer = NULL;
			throw;
		}

		if (length)
			*length = len;

		return buffer;
	}

	void packet::read_buffer(std::vector<byte> &data, const_iterator &it) const
	{
		CHECKSUM_HACK()
		// uses read_buffer normally to store the buffer to a temp byte array
		// which is then copied to the std::vector and deleted
		size_t len;
		byte *rawbuffer = read_buffer(it, &len);

		if (!rawbuffer)
			throw readexception();

		data.resize(len);
		std::copy(rawbuffer, rawbuffer + len, &data[0]);
		delete [] rawbuffer;
	}
}