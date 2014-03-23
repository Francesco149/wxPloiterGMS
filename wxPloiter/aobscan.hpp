#pragma once

#include "common.h"
#include <string>
#include <boost/shared_array.hpp>

namespace utils {
// utilities for memory reading & editing
namespace mem
{
	// scans for a byte array in a given memory region
	class aobscan
	{
	public:
		enum error
		{
			none = 0,
			invalid = 1,
			not_found = 2
		};

		// scans the given array of bytes in the given memory region
		// pattern: a byte pattern with question marks as wildcards, for example "11 AA BB ? CC ? DD"
		// pimagebase: the beginning address of the memory region to scan
		// imagesize: the size of the memory region to scan
		// index: number of occurences to skip
		aobscan(const std::string &pattern, void *pimagebase, size_t imagesize, int index = 0);
		virtual ~aobscan();

		// retuns the address at which the aob was found
		byte *result() const;

		// returns the result of the aob scan
		// values:
		// aobscan::none (0): pattern found correctly
		// aobscan::invalid (1): the pattern is invalid
		// aobscan::not_found (2): the pattern was not found
		error geterror() const;

		// returns the byte array string that was passed at the constructor
		std::string string() const;

		// returns the size of the pattern of bytes in number of bytes
		size_t bytecount() const;

		// returns the byte pattern as a raw byte array with the wildcard bytes set to zero
		boost::shared_array<byte> bytearray() const;

		// returns a mask string for the byte pattern which contains a series of x and ?, 
		// where the x stand for a non-wildcard byte and the ? stand for a wildcard byte
		boost::shared_array<char> maskstring() const;

	protected:
		void countpatternbytes(); // counts the number of bytes in the aob
		bool makepatternmask(); // generates a mask for the aob
		bool makepatternbytes(); // generates the raw byte array for the aob
		void searchpattern(int index); // searches the aob and stores the result in presult

		byte * const pimagebase; // the beginning address of the memory region to scan
		const size_t imagesize; // the size of the memory region to scan
		const std::string pattern; // a byte pattern with question marks as wildcards
		size_t length; // length in bytes of the byte pattern
		byte *presult; // the address at which the aob was found
		error res; // result of the scan
		boost::shared_array<char> mask; // mask string for the byte pattern
		boost::shared_array<byte> data; // byte pattern as a raw byte
	};
}}
