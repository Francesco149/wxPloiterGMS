#include "safeheaderlist.hpp"

#include <boost/thread.hpp>
#include <sstream>
#include "utils.hpp"

namespace wxPloiter
{
	typedef boost::mutex mutex;

	safeheaderlist::ptr safeheaderlist::blockedsend;
	safeheaderlist::ptr safeheaderlist::blockedrecv;
	safeheaderlist::ptr safeheaderlist::ignoredsend;
	safeheaderlist::ptr safeheaderlist::ignoredrecv;

	safeheaderlist::ptr safeheaderlist::getblockedsend()
	{
		return getsingleton(blockedsend);
	}

	safeheaderlist::ptr safeheaderlist::getblockedrecv()
	{
		return getsingleton(blockedrecv);
	}

	safeheaderlist::ptr safeheaderlist::getignoredsend()
	{
		return getsingleton(ignoredsend);
	}

	safeheaderlist::ptr safeheaderlist::getignoredrecv()
	{
		return getsingleton(ignoredrecv);
	}

	std::string safeheaderlist::tostring()
	{
		bool first = true;
		std::ostringstream oss;
		
		oss << "safeheaderlist(" << iv.size() << "): { ";
		boost_foreach(const word &h, iv)
		{
			oss << (first ? "" : ", ") << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << h;
			first = false;
		}
		oss << " }";

		return oss.str();
	}

	safeheaderlist::safeheaderlist()
	{
		// empty
	}

	safeheaderlist::safeheaderlist(safeheaderlist &other)
	{
		other.copy(this);
	}

	safeheaderlist::~safeheaderlist()
	{
		// empty
	}

	void safeheaderlist::push_back(word header)
	{
		mutex::scoped_lock lock(mut);

		if (!v.empty() && v.find(header) != v.end())
			return; // already blocked

		v.insert(header);
		iv.push_back(header);
	}

	void safeheaderlist::erase(word header)
	{
		mutex::scoped_lock lock(mut);
		
		if (v.empty())
			return;

		std::set<word>::iterator it = v.find(header);
		if (it == v.end())
			return; // not blocked

		v.erase(it);
		iv.erase(std::find(iv.begin(), iv.end(), header));
	}

	bool safeheaderlist::contains(word header)
	{
		mutex::scoped_lock lock(mut);

		if (v.empty()) 
			return false;

		return v.find(header) != v.end();
	}

	void safeheaderlist::copy(std::set<word> &dst)
	{
		mutex::scoped_lock lock(mut);
		boost_foreach(const word &h, v)
			dst.insert(h);
	}

	void safeheaderlist::copy(std::vector<word> &dst)
	{
		mutex::scoped_lock lock(mut);
		boost_foreach(const word &h, iv)
			dst.push_back(h);
	}

	void safeheaderlist::copy(safeheaderlist *dst)
	{
		copy(dst->v);
		copy(dst->iv);
	}

	void safeheaderlist::clear()
	{
		mutex::scoped_lock lock(mut);
		v.clear();
	}

	size_t safeheaderlist::size()
	{
		mutex::scoped_lock lock(mut);
		return v.size();
	}

	safeheaderlist::ptr safeheaderlist::getsingleton(ptr &pinstance)
	{
		if (!pinstance.get())
			pinstance.reset(new safeheaderlist);

		return pinstance;
	}

	word &safeheaderlist::at(long index)
	{
		mutex::scoped_lock lock(mut);
		return iv[index];
	}
}
