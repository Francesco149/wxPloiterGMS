#include "mainform.hpp"

#include "packethooks.hpp"
#include "resource.h"
#include "utils.hpp"
#include "safeheaderlist.hpp"

#include <wx/wx.h>
#include <wx/log.h>
#include <wx/sizer.h>
#include <wx/panel.h>
#include <wx/statbox.h>
#include <wx/menu.h>
#include <wx/hyperlink.h>

#include <boost/make_shared.hpp>
#include <boost/lexical_cast.hpp>

#define menu_bind(functor, id) \
	Bind(wxEVT_COMMAND_MENU_SELECTED, functor, this, id);

#define RECV_SYMBOL "<-"
#define SEND_SYMBOL "->"

namespace wxPloiter
{
	// {{{
	// app begin
	const std::string app::logfile = "wxPloiter.log";
	const std::string app::tag = "wxPloiter::app";
	const wxString app::appname = "wxPloiter";
	const wxString app::appver = "r1";

	void app::rundll(HINSTANCE hInstance)
	{
		try
		{
			// placeholder cmd line args
			int argc = 1;
			char *argv[] = { "wxPloiter" };

			// manually run the wxWidgets app
			// (used to deploy as a dll)
			wxPloiter::app *papp = new wxPloiter::app(hInstance);
			wxApp::SetInstance(papp);
			wxEntry(argc, argv);
		}
		catch (const std::exception &e)
		{
			utils::logging::get()->wtf(tag, strfmt() << "unexpected exception: " << e.what());
			fatal();
		}

		FreeLibraryAndExitThread(hInstance, 0); // unload injected dll
	}

	app::app(HINSTANCE hInstance)
		: wxApp(), 
		  cryptoinit("thread_safe=true"), // init botan (only used in winsock mode)
		  hInstance(hInstance)
	{
		// empty
	}

	app::~app()
	{
		// empty
	}

	bool app::OnInit()
	{
		mainform *frame;

		// init logging
		utils::logging::setfilename(logfile.c_str());
		log = utils::logging::get();

		log->i(tag, strfmt() << appname << " " << appver << 
			" - initializing on " << utils::datetime::utc_date() << 
			"T" << utils::datetime::utc_time() << " UTC");

		dbgcode(log->setverbosity(utils::logging::verbose));

		// create main frame
		mainform::init(hInstance, appname, wxDefaultPosition, wxSize(420 /* blaze it faggot */, 490));
		frame = mainform::get();

		if (!frame) // out of memory?
		{
			log->wtf(tag, "OnInit: could not create top-level frame! Are we out of memory?");
			fatal();
			return false;
		}

		// display top level window
		SetTopWindow(frame); // optional (I think)
		frame->Show(); // makes the main frame visible

		utils::random::init();

		// init hooks
		if (!packethooks::get()->isinitialized())
			wxLogWarning("Could not hook some or all of the packet functions. Logging / sending might not work.");

		return true;
	}

	void app::fatal()
	{
		static const wxString msg = "A fatal error has occurred and the application "
			"will now terminate.\nPlease check the log file for more information.";

		wxLogFatalError(msg);
	}
	// app end
	// }}}

	// {{{
	// itemlist begin
	itemlist::itemlist(wxWindow *parent, size_t columncount)
		: wxListView(parent, wxID_ANY, wxDefaultPosition,
			wxDefaultSize, wxLC_REPORT | wxLC_VIRTUAL),
			autoscroll(true), 
			columncount(columncount) // used in push_back
	{
		SetItemCount(0); // initialize the listview as empty

		// default columns
		AppendColumn("dir", wxLIST_FORMAT_LEFT, 50);
		AppendColumn("ret / enc", wxLIST_FORMAT_LEFT, 75);
		AppendColumn("size", wxLIST_FORMAT_LEFT, 50);
		AppendColumn("data", wxLIST_FORMAT_LEFT, 238);

		SetFont(wxFont(8, wxFONTFAMILY_MODERN, wxFONTSTYLE_NORMAL, 
			wxFONTWEIGHT_NORMAL, false, "Consolas"));

		Bind(wxEVT_SIZE, &itemlist::OnSize, this); // adjust the column size on resize

		assert(GetColumnCount() == columncount);
	}

	itemlist::~itemlist()
	{
		// empty
	}

	size_t itemlist::getcolumncount() const
	{
		return columncount;
	}

	void itemlist::push_back(size_t columns, ...)
	{
		va_list va;
		va_start(va, columns);
		boost::shared_array<wxString> it(new wxString[columncount]);

		// append given columns
		for (size_t i = 0; i < columns; i++)
		{
			it[i] = va_arg(va, wxString);
			//utils::logging::get()->i("itemlist", strfmt() << "it[" << i << "] = " << it[i]);
		}

		// missing columns will remain empty

		items.push_back(it);
		va_end(va);

		SetItemCount(GetItemCount() + 1); // update item count

		if (autoscroll)
			EnsureVisible(GetItemCount() - 1);
	}

	void itemlist::clear()
	{
		items.clear();
		SetItemCount(0);
		Refresh();
	}

	boost::shared_array<wxString> itemlist::at(long index)
	{
		return items[index];
	}

	void itemlist::setautoscroll(bool autoscroll)
	{
		this->autoscroll = autoscroll;
	}

	wxString itemlist::OnGetItemText(long item, long column) const
	{
		//utils::logging::get()->i("itemlist", strfmt() << "getting items[" << item << "][" << column << "]");
		return items[item][column];
	}

	void itemlist::OnSize(wxSizeEvent& e)
	{
		// make last column fill up available space
		this->SetColumnWidth(columncount - 1, 
			e.GetSize().GetWidth() 
			- 50 * (columncount - 1) // size of the first columns (always 50 in my case)
			- 25 // prevents horizontal scrollbar from popping up
			- 25 // recently made the "enc" column larger
		);
	}
	// itemlist end
	// }}}

	// {{{
	// wxPacketEvent begin
	wxPacketEvent::wxPacketEvent(wxEventType commandType, int id)
		:  wxCommandEvent(commandType, id), 
		   decrypted(false)
	{ 
		// empty
	}
 
	wxPacketEvent::wxPacketEvent(const wxPacketEvent &event)
		: wxCommandEvent(event), 
		  p(event.GetPacket()), 
		  decrypted(event.IsDecrypted()) // only used in winsock mode
	{ 
		// copy ctor
	}

	wxPacketEvent::~wxPacketEvent()
	{
		// empty
	}
 
	wxEvent *wxPacketEvent::Clone() const 
	{ 
		// wrapper for copy ctor
		return new wxPacketEvent(*this); 
	}
 
	boost::shared_ptr<maple::packet> wxPacketEvent::GetPacket() const 
	{ 
		return p; 
	}

	bool wxPacketEvent::IsDecrypted() const
	{
		return decrypted;
	}

	void *wxPacketEvent::GetReturnAddress() const
	{
		return retaddy;
	}

	void wxPacketEvent::SetPacket(boost::shared_ptr<maple::packet> p) 
	{ 
		this->p = p; 
	}

	void wxPacketEvent::SetDecrypted(bool decrypted)
	{
		this->decrypted = decrypted;
	}

	void wxPacketEvent::SetReturnAddress(void *retaddy)
	{
		this->retaddy = retaddy;
	}
	// wxPacketEvent end
	// }}}

	// {{{
	// mainform begin
	const std::string mainform::tag = "wxPloiter::mainform";
	mainform *mainform::inst;

	void mainform::init(HINSTANCE hInstance, const wxString &title, 
		const wxPoint &pos, const wxSize &size)
	{
		if (inst)
			return;

		inst = new mainform(hInstance, title, pos, size);
	}

	mainform *mainform::get()
	{
		return inst;
	}

	mainform::mainform(HINSTANCE hInstance, const wxString &title, 
		const wxPoint &pos, const wxSize &size)
		: wxFrame(NULL, wxID_ANY, title, pos, size),
		  log(utils::logging::get()),
		  hInstance(hInstance), // used for LoadIcon
		  packets(NULL), // packet listview
		  logsend(false), // log send toggle
		  logrecv(false), // log recv toggle
		  loggingmenu(NULL), // logging menu
		  packetmenu(NULL), // packet menu
		  packettext(NULL), // inject packet textbox
		  spamdelay(NULL), // spam delay textbox
		  hdlg(NULL) // headers dialog
	{
		//SetMinSize(size);

		wxPanel *basepanel = new wxPanel(this);
		wxBoxSizer *basesizer = new wxBoxSizer(wxVERTICAL);

		// we're on windows, so who cares about dealing with cross-platform icons
		// this is the only way that seems to work to set icon in an injected dll
		HWND hWnd = GetHWND();
		HICON hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));

		SendMessage(hWnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hIcon));
		SendMessage(hWnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hIcon));

		log->i(tag, "mainform: initializing controls");

		// create menu bar
		wxMenuBar *mbar = new wxMenuBar;

		// file menu
		wxMenu *menu = new wxMenu;
		menu->AppendCheckItem(wxID_FILE_HIDEMAPLE, "Hide MapleStory");
		menu->Append(wxID_FILE_EXIT, "Exit");
		mbar->Append(menu, "File"); // add menu to the menu 

		// bind menu events
		menu_bind(&mainform::OnFileHideMapleClicked, wxID_FILE_HIDEMAPLE);
		menu_bind(&mainform::OnFileExitClicked, wxID_FILE_EXIT);

		// logging menu
		menu = new wxMenu;
		wxMenuItem *ascroll = menu->AppendCheckItem(wxID_LOGGING_AUTOSCROLL, "Autoscroll");
		ascroll->Check(true);
		menu->Append(wxID_LOGGING_CLEAR, "Clear");
		menu->AppendCheckItem(wxID_LOGGING_SEND, "Log send");
		menu->AppendCheckItem(wxID_LOGGING_RECV, "Log recv");
		mbar->Append(menu, "Logging"); // add menu to the menu bar
		loggingmenu = menu;

		// bind menu events
		menu_bind(&mainform::OnLoggingAutoscrollClicked, wxID_LOGGING_AUTOSCROLL);
		menu_bind(&mainform::OnLoggingClearClicked, wxID_LOGGING_CLEAR);
		menu_bind(&mainform::OnLoggingSendClicked, wxID_LOGGING_SEND);
		menu_bind(&mainform::OnLoggingRecvClicked, wxID_LOGGING_RECV);

		// packet menu
		menu = new wxMenu;
		menu->Append(wxID_PACKET_COPY, "Copy to clipboard");
		menu->Append(wxID_PACKET_COPYRET, "Copy return address to clipboard");
		menu->Append(wxID_PACKET_HEADERLIST, "Header list");
		menu->Append(wxID_PACKET_IGNORE, "Ignore header");
		menu->Append(wxID_PACKET_BLOCK, "Block header");
		//menu->AppendCheckItem(wxID_PACKET_ENABLESENDBLOCK, "Send blocking hook (requires bypass)");
		mbar->Append(menu, "Packet"); // add menu to the menu bar
		packetmenu = menu;

		menu_bind(&mainform::OnPacketCopyClicked, wxID_PACKET_COPY);
		menu_bind(&mainform::OnPacketCopyRetClicked, wxID_PACKET_COPYRET);
		menu_bind(&mainform::OnPacketHeaderListClicked, wxID_PACKET_HEADERLIST);
		menu_bind(&mainform::OnPacketIgnoreClicked, wxID_PACKET_IGNORE);
		menu_bind(&mainform::OnPacketBlockClicked, wxID_PACKET_BLOCK);
		//menu_bind(&mainform::OnPacketEnableSendBlockClicked, wxID_PACKET_ENABLESENDBLOCK);

		// help menu
		menu = new wxMenu;
		menu->Append(wxID_HELP_ABOUT, "About");
		mbar->Append(menu, "Help"); // add menu to the menu bar

		// bind menu events
		menu_bind(&mainform::OnHelpAboutClicked, wxID_HELP_ABOUT);

		// add menu bar to frame
		SetMenuBar(mbar);

		// status bar (the thing at the bottom of the window)
		CreateStatusBar();

		wxStaticBoxSizer *packetsbox = new wxStaticBoxSizer(wxVERTICAL,
			basepanel, "Packet Log");
		{
			wxStaticBox *box = packetsbox->GetStaticBox();

			// controls
			packets = new itemlist(box, 4);
			packets->Bind(wxEVT_LIST_ITEM_SELECTED, &mainform::OnPacketSelected, this);
			packetsbox->Add(packets, 1, wxALL | wxEXPAND, 10);
		}

		wxStaticBoxSizer *injectbox = new wxStaticBoxSizer(wxVERTICAL,
			basepanel, "Inject Packets (multiline)");
		{
			wxStaticBox *box = injectbox->GetStaticBox();

			// FUCK I spent like 2 hours trying to figure out what was wrong with the packet sender to discover 
			// that the text wrapping was causing the wrapped newlines to be treated as multiline packets
			packettext = new wxTextCtrl(box, wxID_ANY, wxEmptyString, 
				wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_DONTWRAP);
			packettext->SetFont(packets->GetFont());

			// horizontal sizer for the two buttons
			wxBoxSizer *buttons = new wxBoxSizer(wxHORIZONTAL);
			{
				choices.Add("Send");
				choices.Add("Recv");
				combobox = new wxComboBox(box, wxID_ANY, "Send", wxDefaultPosition, 
					wxDefaultSize, choices, wxCB_READONLY);

				sendpacket = new wxButton(box, wxID_ANY, "Inject");
				sendpacket->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &mainform::OnInjectPacketClicked, this);

				wxCheckBox *spam = new wxCheckBox(box, wxID_ANY, "Spam");
				spamdelay = new wxTextCtrl(box, wxID_ANY, "20");
				spam->Bind(wxEVT_COMMAND_CHECKBOX_CLICKED, &mainform::OnSpamClicked, this);

				buttons->Add(sendpacket, 0, wxTOP | wxRIGHT, 5);
				buttons->Add(combobox, 0, wxTOP | wxRIGHT | wxLEFT | wxALIGN_CENTER_VERTICAL, 5);
				buttons->Add(spamdelay, 0, wxTOP | wxLEFT | wxALIGN_CENTER_VERTICAL, 5);
				buttons->Add(spam, 0, wxTOP | wxLEFT | wxALIGN_CENTER_VERTICAL, 5);
			}

			injectbox->Add(packettext, 2, wxLEFT | wxRIGHT | wxTOP | wxEXPAND, 10);
			injectbox->Add(buttons, 1, wxLEFT | wxRIGHT | wxBOTTOM, 10);
		}

		wxBoxSizer *begsizer = new wxBoxSizer(wxHORIZONTAL);
		{
			wxStaticText *begging0 = new wxStaticText(basepanel, wxID_ANY, "Like my releases?");
			wxHyperlinkCtrl *begging1 = new wxHyperlinkCtrl(basepanel, wxID_ANY, "donate", 
				"https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=5E289LJ5UUG3Q");
			wxStaticText *begging2 = new wxStaticText(basepanel, wxID_ANY, "or");
			wxHyperlinkCtrl *begging3 = new wxHyperlinkCtrl(basepanel, wxID_ANY, "buy my cheap meso", 
				"https://ccplz.net/threads/s-meso-16%E2%82%AC-b-taxes-covered-paypal-btc-ltc-doge.60888/");

			begsizer->Add(begging0, 0, wxRIGHT, 5);
			begsizer->Add(begging1, 0, wxRIGHT, 5);
			begsizer->Add(begging2, 0, wxRIGHT, 5);
			begsizer->Add(begging3, 0, wxRIGHT, 0);
		}

		basesizer->Add(packetsbox, 1, wxALL | wxEXPAND, 10);
		basesizer->Add(injectbox, 0, wxLEFT | wxRIGHT | wxBOTTOM | wxEXPAND, 10);
		basesizer->Add(begsizer, 0, wxLEFT | wxRIGHT | wxBOTTOM | wxEXPAND, 10);
		basepanel->SetAutoLayout(true);
		basepanel->SetSizer(basesizer);
		basepanel->Layout(); // fixes the layout snapping into place after the first resize

		// bind window events
		Bind(wxEVT_CLOSE_WINDOW, &mainform::OnClose, this);
		Bind(wxEVT_MENU_OPEN, &mainform::OnMenuOpened, this); // will keep the menu updated

		// bind custom events
		Bind(wxEVT_PACKET_LOGGED, &mainform::OnPacketLogged, this, wxID_PACKET_SEND);
		Bind(wxEVT_PACKET_LOGGED, &mainform::OnPacketLogged, this, wxID_PACKET_RECV);

		// create child dialogs
		hdlg = new headerdialog(this);

		wxLogStatus("Idle.");
	}

	mainform::~mainform()
	{
		// empty
	}

	/*
	void mainform::enablesendblockingtoggle(bool enabled)
	{
		loggingmenu->Enable(wxID_PACKET_ENABLESENDBLOCK, enabled);
	}
	*/

	void mainform::enablechoice(const wxString &choice, bool enabled)
	{
		bool found = choices.Index(choice) != wxNOT_FOUND;

		wxString current = combobox->GetValue();

		if (enabled && !found)
			choices.Add(choice);

		else if (!enabled && found)
			choices.Remove(choice);

		combobox->Clear();
		combobox->Append(choices);

		if (!choices.size())
			sendpacket->Enable(false);
		
		else
			sendpacket->Enable(true);

		if (choices.Index(current) != wxNOT_FOUND)
			combobox->SetValue(current);
	}

	void mainform::enablesend(bool enabled)
	{
		enablechoice("Send", enabled);
	}

	void mainform::enablerecv(bool enabled)
	{
		enablechoice("Recv", enabled);
	}

	void mainform::queuepacket(boost::shared_ptr<maple::packet> p, int id, bool decrypted, void *retaddy)
	{
		// post custom packet log event to the gui
		// this is thread safe
		wxPacketEvent *event = new wxPacketEvent(wxEVT_PACKET_LOGGED, id);
		event->SetEventObject(mainform::get());
		event->SetPacket(p);
		event->SetDecrypted(decrypted);
		event->SetReturnAddress(retaddy);
		wxQueueEvent(mainform::get(), event);
	}

	void mainform::OnPacketLogged(wxPacketEvent &e)
	{
		//log->i(tag, "processing packet event");

		const char *direction = NULL;
		word header = 0;
		boost::shared_ptr<maple::packet> p = e.GetPacket();

		try
		{
			maple::packet::iterator it = p->begin();
			p->read<word>(&header, it);
		}
		catch (const maple::readexception &)
		{
			log->w(tag, "OnPacketLogged: failed to read packet header!");
			return;
		}

		switch (e.GetId())
		{
		case wxID_PACKET_RECV:
			if (!logrecv || safeheaderlist::getignoredrecv()->contains(header))
				return;

			direction = RECV_SYMBOL;
			break;

		case wxID_PACKET_SEND:
			if (!logsend || safeheaderlist::getignoredsend()->contains(header))
				return;

			direction = SEND_SYMBOL;
			break;

		default:
			assert(false);
			break;
		}

		packets->push_back(4, 
			wxString(direction), 

			packethooks::get()->isusingwsock() ? 
				wxString(e.IsDecrypted() ? "no" : "yes") 
			: 
				wxString::Format("0x%08X", reinterpret_cast<dword>(e.GetReturnAddress())),

			wxString::Format("%lu", p->size()), 
			wxString(p->tostring())
		);
	}

	void mainform::OnInjectPacketClicked(wxCommandEvent &e)
	{
		if (packettext->GetValue().IsEmpty())
		{
			wxLogError("Please enter a packet.");
			return;
		}

		if (combobox->GetValue().IsEmpty())
		{
			wxLogError("Please select a direction.");
			return;
		}

		boost::shared_ptr<packethooks> ph = packethooks::get();
		bool recv = (combobox->GetValue().Cmp("Recv") == 0);

		try
		{
			for (int i = 0; i < packettext->GetNumberOfLines(); i++)
			{
				maple::packet p;

				if (recv)
				{
					// generate random recv header
					dword dwHeader = utils::random::get()->getdword();
					p.append<dword>(dwHeader);
					p.append_data(packettext->GetLineText(i).ToStdString());
					ph->recvpacket(p);
				}
				else
				{
					p.append_data(packettext->GetLineText(i).ToStdString());
					ph->sendpacket(p);
				}

				log->i(tag, strfmt() << "OnInjectPacketClicked: injected " << 
					combobox->GetValue().ToStdString() << " " << p.tostring());
			}
		}
		catch (std::exception &e)
		{
			wxLogError("Invalid packet: %s.", wxString(e.what()));
		}
	}

	void mainform::packetspamthread(boost::shared_array<maple::packet> lines, dword count, dword delay, bool recv)
	{
		namespace tt = boost::this_thread;
		namespace pt = boost::posix_time;

		boost::shared_ptr<packethooks> ph = packethooks::get();

		while (true)
		{
			for (dword i = 0; i < count; i++)
			{
				if (recv)
					ph->recvpacket(lines[i]);
				else
					ph->sendpacket(lines[i]); // TODO: multisend delay between each line
			}

			tt::sleep(pt::milliseconds(delay));
		}
	}

	void mainform::OnSpamClicked(wxCommandEvent &e)
	{
		if (combobox->GetValue().IsEmpty())
		{
			wxLogError("Please select a direction.");
			return;
		}

		bool recv = combobox->GetValue().Cmp("Recv") == 0;

		if (hpacketspam.get())
		{
			hpacketspam->interrupt();
			hpacketspam.reset();
		}

		if (!e.IsChecked())
			return;

		dword datspamdelay;

		try   
		{
			datspamdelay = boost::lexical_cast<int>(spamdelay->GetValue().ToStdString());
		}
		catch(boost::bad_lexical_cast &e)
		{
			wxLogError("Invalid spam delay: %s.", wxString(e.what()));
			return;
		}

		try
		{
			boost::shared_array<maple::packet> lines(new maple::packet[packettext->GetNumberOfLines()]);

			for (int i = 0; i < packettext->GetNumberOfLines(); i++)
			{
				if (recv)
				{
					// generate random recv header
					dword dwHeader = utils::random::get()->getdword();
					lines[i].append<dword>(dwHeader);
					lines[i].append_data(packettext->GetLineText(i).ToStdString());
				}
				else
					lines[i].append_data(packettext->GetLineText(i).ToStdString());
				
				log->i(tag, strfmt() << "OnSpamClicked: parsed " << combobox->GetValue().ToStdString() << " " << lines[i].tostring());
			}

			hpacketspam = boost::make_shared<boost::thread>(
				boost::bind(&mainform::packetspamthread, this, lines, packettext->GetNumberOfLines(), datspamdelay, recv)
			);
		}
		catch (std::exception &e)
		{
			wxLogError("Invalid packet: %s.", wxString(e.what()));
		}
	}

	void mainform::OnFileHideMapleClicked(wxCommandEvent &e)
	{
		HWND hMoopla = maple::getwnd();
		ShowWindow(hMoopla, e.IsChecked() ? SW_HIDE : SW_SHOW);
	}

	void mainform::OnFileExitClicked(wxCommandEvent &e)
	{
		wxLogStatus("Terminating");
		Close(false);
	}

	void mainform::OnLoggingAutoscrollClicked(wxCommandEvent &e)
	{
		packets->setautoscroll(e.IsChecked());
	}

	void mainform::OnLoggingClearClicked(wxCommandEvent &e)
	{
		packets->clear();
	}

	void mainform::OnLoggingSendClicked(wxCommandEvent &e)
	{
		logsend = e.IsChecked();
	}

	void mainform::OnLoggingRecvClicked(wxCommandEvent &e)
	{
		logrecv = e.IsChecked();
	}

	void mainform::OnPacketCopyClicked(wxCommandEvent &e)
	{
		long sel = packets->GetFirstSelected();
		assert(sel != -1);

		// store selected packet to the clipboard
		utils::copytoclipboard(
			new wxTextDataObject(
				packets->at(sel)[packets->getcolumncount() - 1]
			)
		);
	}

	void mainform::OnPacketCopyRetClicked(wxCommandEvent &e)
	{
		long sel = packets->GetFirstSelected();
		assert(sel != -1);

		// store selected packet to the clipboard
		utils::copytoclipboard(
			new wxTextDataObject(
				packets->at(sel)[packets->getcolumncount() - 3]
			)
		);
	}

	void mainform::OnPacketHeaderListClicked(wxCommandEvent &e)
	{
		hdlg->Show();
	}

	void mainform::OnPacketIgnoreClicked(wxCommandEvent &e)
	{
		// TODO: join with func below

		safeheaderlist::ptr plist; // send/recv ignore list
		long sel = packets->GetFirstSelected();
		
		if (sel == -1)
			return;

		maple::packet p;

		try
		{
			boost::shared_array<wxString> sitem = packets->at(sel);
			bool recv = sitem[0].Cmp(RECV_SYMBOL) == 0;

			plist = recv ? safeheaderlist::getignoredrecv() : safeheaderlist::getignoredsend();
			p.append_data(sitem[packets->getcolumncount() - 1].ToStdString());

			if (p.size() < 2)
				throw std::invalid_argument("Invalid packet selected! Is this a bug?");

			log->i(tag, strfmt() << "OnPacketIgnoreClicked: ignoring " << p.tostring());
			plist->push_back(*reinterpret_cast<word *>(p.raw()));
			hdlg->refresh();
		}
		catch (std::exception &e)
		{
			wxLogError("Invalid header: %s.", wxString(e.what()));
		}
	}

	void mainform::OnPacketBlockClicked(wxCommandEvent &e)
	{
		safeheaderlist::ptr plist; // send/recv block list
		long sel = packets->GetFirstSelected();
		
		if (sel == -1)
			return;

		maple::packet p;

		try
		{
			boost::shared_array<wxString> sitem = packets->at(sel);
			bool recv = sitem[0].Cmp(RECV_SYMBOL) == 0;

			plist = recv ? safeheaderlist::getblockedrecv() : safeheaderlist::getblockedsend();
			p.append_data(sitem[packets->getcolumncount() - 1].ToStdString());

			if (p.size() < 2)
				throw std::invalid_argument("Invalid packet selected! Is this a bug?");

			log->i(tag, strfmt() << "OnPacketBlockClicked: blocking " << p.tostring());
			plist->push_back(*reinterpret_cast<word *>(p.raw()));
			hdlg->refresh();
		}
		catch (std::exception &e)
		{
			wxLogError("Invalid header: %s.", wxString(e.what()));
		}
	}

	/*
	void mainform::OnPacketEnableSendBlockClicked(wxCommandEvent &e)
	{
		packethooks::get()->enablesendblock(e.IsChecked());
	}
	*/

	void mainform::OnHelpAboutClicked(wxCommandEvent &e)
	{
		wxString ver = wxString::Format("%s %s", app::appname, app::appver);

		wxMessageBox(
			wxString::Format("%s\n\n"
				"coded by Francesco \"Franc[e]sco\" Noferi\n"
				"http://sabishiimedia.wordpress.com/\n"
				"francesco1149@gmail.com", ver),
			ver, wxICON_INFORMATION | wxOK, this
		);
	}

	void mainform::OnClose(wxCloseEvent &e)
	{
		if (e.CanVeto()) // forced termination should not ask to kill maple
		{
			int res = wxMessageBox("This will also shut down MapleStory. Are you sure?", 
				app::appname, wxICON_INFORMATION | wxYES_NO, this);

			if (res == wxYES)
				TerminateProcess(GetCurrentProcess(), EXIT_SUCCESS);

			e.Veto();
			return;
		}

		e.Skip();
	}

	void mainform::OnMenuOpened(wxMenuEvent &e)
	{
		// toggle menu items that are only usable when a packet is selected
		bool enable = packets->GetFirstSelected() != -1;
		packetmenu->Enable(wxID_PACKET_COPY, enable);
		packetmenu->Enable(wxID_PACKET_IGNORE, enable);
		packetmenu->Enable(wxID_PACKET_BLOCK, enable);
		e.Skip(); // not sure if this is really necessary
	}

	void mainform::OnPacketSelected(wxListEvent &e)
	{
		long sel = packets->GetFirstSelected();
		assert(sel != -1);

		// store selected packet to the textbox
		boost::shared_array<wxString> sitem = packets->at(sel);
		packettext->SetValue(sitem[packets->getcolumncount() - 1]);

		wxString direction = sitem[0].Cmp(RECV_SYMBOL) == 0 ? "Recv" : "Send";

		if (choices.Index(direction) != wxNOT_FOUND)
			combobox->SetValue(direction);
	}
	// mainform end
	// }}}
}