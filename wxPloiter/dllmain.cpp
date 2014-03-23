#include "mainform.hpp"
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
		boost::shared_ptr<boost::thread> t = boost::make_shared<boost::thread>(
			wxPloiter::app::rundll, reinterpret_cast<HINSTANCE>(hModule));
 
    return TRUE;
}
