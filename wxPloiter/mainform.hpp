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

#include "logging.hpp"
#include "packet.hpp"
#include "packetstruct.h"
#include "headerdialog.hpp"

#include <wx/app.h>
#include <wx/frame.h>
#include <wx/listctrl.h>
#include <wx/button.h>

#include <boost/shared_array.hpp>
#include <boost/thread.hpp>

#include <list>

namespace wxPloiter
{
	// represents the application and all of its windows as a whole
	// contains global information about the application and is 
	// responsible for initializing the program on startup
	class app : public wxApp
	{
	public:
		static const wxString appname; // application name
		static const wxString appver; // application version

		app(HINSTANCE hInstance);
		virtual ~app();
		static void rundll(HINSTANCE hInstance); // deploys the application as a dll
		HINSTANCE getinstance();
		virtual bool OnInit(); // called on startup
		static void fatal(); // displays a fatal error message and terminates the program

	protected:
		static const std::string logfile;
		static const std::string tag;
		boost::shared_ptr<utils::logging> log;
		HINSTANCE hInstance;
	};

	// a custom virtual listview that retrieves values directly from an array
	// this ensures excellent performance with no lag whatsoever when scrolling
	// huge amounts of data that is updated in real time
	class itemlist : public wxListView
	{
	public:
		itemlist(wxWindow *parent, size_t columncount);
		virtual ~itemlist();
		void push_back(size_t columns, ...); // appends an item with the given variable number of columns
		void clear(); // clears the list
		boost::shared_array<wxString> at(long index); // returns the item at the given index
		void setautoscroll(bool autoscroll); // toggles auto scrolling to the bottom
		size_t getcolumncount() const;

		// fires when the listview is being drawn, it's used by wxListView to obtain
		// the text for the given item and column
		wxString OnGetItemText(long item, long column) const;

		// fires when the listview is resized
		// used to make the last column fill up the remaining space
		void OnSize(wxSizeEvent& e);

	protected:
		std::vector<
			boost::shared_array<wxString>
		> items; // internal item list
		bool autoscroll;
		size_t columncount;
	};

	// a custom event that transports a whole maple::packet
	class wxPacketEvent: public wxCommandEvent
	{
	public:
		wxPacketEvent(wxEventType commandType, int id = 0);
		wxPacketEvent(const wxPacketEvent &event); // copy constructor. required
		virtual ~wxPacketEvent();
		wxEvent *Clone() const; // clone the current instance and custom data. required
		boost::shared_ptr<maple::packet> GetPacket() const;
		bool IsDecrypted() const;
		void *GetReturnAddress() const;
		void SetPacket(boost::shared_ptr<maple::packet> p);
		void SetDecrypted(bool decrypted);
		void SetReturnAddress(void *retaddy);
 
	private:
		boost::shared_ptr<maple::packet> p;
		bool decrypted;
		void *retaddy;
	};

	// custom event types
	wxDEFINE_EVENT(wxEVT_PACKET_LOGGED, wxPacketEvent);

	class mainform : public wxFrame
	{
	public:
		// menu ids, used for event handling
		enum
		{
			// file
		    wxID_FILE_EXIT = 1,
			wxID_FILE_SAVECFG,
			wxID_FILE_SAVECFGAS,
			wxID_FILE_LOADCFG,
			wxID_FILE_HIDEMAPLE, 

		    // logging
			wxID_LOGGING_AUTOSCROLL,
		    wxID_LOGGING_CLEAR,
			wxID_LOGGING_SEND,
			wxID_LOGGING_RECV, 
			wxID_LOGGING_HOOKSEND, 
			wxID_LOGGING_HOOKRECV, 

			// packet
			wxID_PACKET_COPY,
			wxID_PACKET_COPYRET, 
			wxID_PACKET_HEADERLIST, 
			wxID_PACKET_IGNORE,
			wxID_PACKET_BLOCK,

			// settings
			wxID_SETTINGS_COPYPACKETS, 

		    // help
		    wxID_HELP_ABOUT,

			// custom events
			wxID_PACKET_SEND,
			wxID_PACKET_RECV
		};

		static void init(HINSTANCE hInstance, const wxString &title, 
			const wxPoint &pos, const wxSize &size); // initializes the singleton
		static mainform *get(); // returns the singleton instance
		virtual ~mainform();
		//void enablesendblockingtoggle(bool enabled);
		void enablesend(bool enabled);
		void enablerecv(bool enabled);
		void queuepacket(boost::shared_ptr<maple::packet> p, int id, bool decrypted, void *retaddy); // queues a packet for logging

	protected:
		static const std::string tag;
		static mainform *inst; // singleton instance

		boost::shared_ptr<utils::logging> log;
		HINSTANCE hInstance; // dll HMODULE
		itemlist *packets; // packet listview
		bool logsend; // send logging toggle
		bool logrecv; // recv logging toggle
		bool copypackets; // if true, the PE will automatically copy clicked packets to the textbox
		wxMenuItem *ascroll; // autoscroll menu entry
		wxMenu *loggingmenu; // ptr to the logging menu
		wxMenu *packetmenu; // pointer to the packet menu
		wxMenuItem *copythosepackets; // copy packets menu entry
		wxMenu *settingsmenu; // pointer to the settings menu
		wxButton *sendpacket; // inject packet button
		wxTextCtrl *packettext; // packet to be injected
		wxTextCtrl *spamdelay; // spam delay textbox
		wxTextCtrl *linedelay; // delay between each line
		wxComboBox *combobox; // send/recv combobox
		wxCheckBox *spamcb; // spam checkbox
		headerdialog *hdlg; // dialog to manage blocked/ignored headers
		boost::shared_ptr<boost::thread> hpacketspam; // thread that spams packets
		wxArrayString choices; // injection combobox choices

		mainform(HINSTANCE hInstance, const wxString &title, const wxPoint &pos, const wxSize &size);
		void loadcfg(const char *file);
		void savecfg(const char *file);
		void enablechoice(const wxString &choice, bool enabled);

		// custom events
		void OnPacketLogged(wxPacketEvent &e);

		// buttons
		void injectpackets(bool spam = false);
		void OnInjectPacketClicked(wxCommandEvent &e);
		void packetspamthread(boost::shared_ptr<std::list<maple::packet>> lines, 
			dword delay, dword linedelay, bool recv, bool single);
		void OnSpamClicked(wxCommandEvent &e);

		// menu events
		void OnFileSaveCfgClicked(wxCommandEvent &e);
		void OnFileSaveCfgAsClicked(wxCommandEvent &e);
		void OnFileLoadCfgClicked(wxCommandEvent &e);
		void OnFileHideMapleClicked(wxCommandEvent &e);
		void OnFileExitClicked(wxCommandEvent &e);

		void OnLoggingAutoscrollClicked(wxCommandEvent &e);
		void OnLoggingClearClicked(wxCommandEvent &e);
		void OnLoggingSendClicked(wxCommandEvent &e);
		void OnLoggingRecvClicked(wxCommandEvent &e);

		void OnPacketCopyClicked(wxCommandEvent &e);
		void OnPacketCopyRetClicked(wxCommandEvent &e);
		void OnPacketHeaderListClicked(wxCommandEvent &e);
		void OnPacketIgnoreClicked(wxCommandEvent &e);
		void OnPacketBlockClicked(wxCommandEvent &e);
		//void OnPacketEnableSendBlockClicked(wxCommandEvent &e);

		void OnSettingsCopyPacketsClicked(wxCommandEvent &e);

		void OnHelpAboutClicked(wxCommandEvent &e);

		// window events
		void OnClose(wxCloseEvent& e);
		void OnMenuOpened(wxMenuEvent &e);
		void OnPacketSelected(wxListEvent &e);
	};
}
