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

#pragma once

#include "common.h"

#include <vector>
#include <iterator>
#include <boost/shared_ptr.hpp>

// this should fix the order of the bytes on little endian OSes
// when packing multibyte values as little endian into the packets
#ifdef BOOST_LITTLE_ENDIAN
#define endiansafe_copy reverse_copy
#else
#define endiansafe_copy copy
#endif

namespace maple
{
	// thrown when a packet fails to read the expected data
	class readexception 
		: public std::out_of_range
	{
	public:
		explicit readexception();
	};

	// represents a maplestory unecrypted packet
	// contains utilities to pack and unpack values from the packet
	// ensures correct endian-ness of the packed values
	class packet
	{
	public:
		typedef boost::shared_ptr<packet> shared_ptr;
		typedef std::vector<byte>::iterator iterator; // for iteration and manipulation of the raw data
		typedef std::vector<byte>::const_iterator const_iterator; // for iteration of the const raw data

		packet();
		virtual ~packet();
		packet(const packet &other); // copy constructor
		packet(const byte *pdata, size_t cb); // initializes the packet with a copy of the given data
		packet(const std::vector<byte> &data); // stl overload of packet(const byte *, size_t)

		size_t size() const; // retuns the size in bytes of the packet
		void clear();

		// returns a pointer to the raw data of the packet. the pointed data 
		// is only guaranteed to exist as long as the packet instance exists
		byte *raw();
		const byte *raw() const; // const overload of byte *packet::data()

		iterator begin(); // returns an iterator to the first byte of the packet's raw data
		iterator end(); // returns an iterator to the end of the packet's raw data
		const_iterator begin() const; // const overload of begin()
		const_iterator end() const; // const overload of end()
		std::string tostring() const; // formats the packet raw data into a string

		// appends the raw data of any type and packs it as little endian
		template <typename T>
		void append(T value)
		{
			byte *raw_value = reinterpret_cast<byte *>(&value); // pointer to the raw bytes of the value
			data.reserve(data.size() + sizeof(T)); // reserve space in the packet data array
			std::endiansafe_copy(raw_value, raw_value + sizeof(T), std::back_inserter(data));
			// copy new data (raw_value to raw_value + size of the data) to the space we reserved at the 
			// end of the data array. back_inserter ensures that the data is appended at the end of the 
			// array and correctly allocated before writing to the new memory
		}

		// packs a new byte into the packet
		// this specializes append<typename> for byte since we don't need to loop
		// and copy through the data for a single byte
		template <>
		void append<byte>(byte b)
		{
			data.push_back(b);
		}

		void append_data(std::string hexstring); // converts a string to raw data to append

		// appends a copy of the given raw data to the packet
		// generally used for null terminated buffers/strings
		// note: this does not pack the size of the raw data into the packet.
		//		 use append_buffer for data buffers with a nonstatic size
		//		 or that are not null-terminated
		void append_data(const byte *pdata, size_t cb);

		void append_data(const std::vector<byte> &data); // stl overload of append_data(const byte *, size_t)
		void append_string(const char *pstr, word len); // pack a string into the packet
		void append_string(const std::string &str); // stl overload of append_string(const char *, word)

		// this allows quick formatting of strings on the fly
		bool append_string(const std::basic_ostream<char> &format);

		// pack a copy of the byte array into the packet
		// note: this also packs the size of the given buffer
		// internally used by append_string
		// I'm not sure maple even uses these kind of buffers, most of the time it uses null terminated buffers
		// which you can append using append_data (making sure it's actually null terminated)
		void append_buffer(const byte *pdata, word cb);

		bool append_buffer(const std::vector<byte> &data); // oload of append_buffer(const byte *, word)

		// reads a value of any given type at the iterator position and increases the iterator
		template <typename T>
		void read(T *pvalue, const_iterator &it) const
		{
			// reached end of packet?
			if (it + sizeof(T) - 1 >= data.end())
				throw readexception();

			// see append<T> to understand how the copy function works
			std::endiansafe_copy(it, it + sizeof(T), reinterpret_cast<byte *>(pvalue));

			it += sizeof(T); // increase iterator by the byte count of our value type
		}

		// reads given num of bytes and incs the it
		// internally used by read_string
		// throws readexception on failure
		void read_data(byte *pdata, size_t cb, const_iterator &it) const;

		// stl overloadload of read_data(byte *, size_t, const_iterator &)
		// note: this function automatically calls .resize on data
		// throws readexception on failure
		void read_data(std::vector<byte> &data, size_t cb, const_iterator &it) const;

		// allocates a new byte array and copies raw data from the packet until a null (zero) byte is reached
		// note: the caller is responsible for deleting the returned array.
		// returns NULL if any error occurs
		// optionally stores resulting buffer length in the given pointer
		// throws readexception on failure
		byte *read_data_nullterminated(const_iterator &it, size_t *length = NULL) const;

		// stl overload of read_data_nullterminated(const_iterator &)
		// note: this automatically calls .resize on data
		// throws readexception on failure
		void read_data_nullterminated(std::vector<byte> &data, const_iterator &it) const;

		// reads a string, allocates a new char array and copies the string to it. optionally stores
		// the string length in the given ptr. also increases the iterator as usual.
		// note: the caller is responsible for deleting the returned array.
		// returns NULL if any error occurs
		// throws readexception on failure
		char *read_string(const_iterator &it, size_t *length = NULL) const;

		// reads a string, copies it to the given stl container and increases the iterator.
		// throws readexception on failure
		void read_string(std::string &str, const_iterator &it) const;

		// reads a buffer, allocates a new byte array and copies the buffer to it. optionally stores
		// the buffer length in the given ptr. also increases the iterator as usual.
		// note: the caller is responsible for deleting the returned array.
		// returns NULL if any error occurs
		// throws readexception on failure
		byte *read_buffer(const_iterator &it, size_t *length = NULL) const;

		// reads a buffer, copies it to the given stl container and increases the iterator.
		// note: this function automatically calls .resize on data
		// throws readexception on failure
		void read_buffer(std::vector<byte> &data, const_iterator &it) const;

	protected:
		std::vector<byte> data; // raw packet data. should we make this a shared_ptr or shared_array?
	};
}
