import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW
from pyplayground import G
from com.t_arn.pymod.ui.window import TaWindow, TaGui
import sys
from spectre_algorithm import spectreTypes, spectre


class MainGui(TaGui):

    def __init__(self, app, parentGui, title, **kwargs):
        super().__init__(app, parentGui, title, **kwargs)
        self.main_box = None
        self.message_area = None
        self._state_data = {}
        self.ti_name = None
        self.ti_masterpw = None
        self.ti_site = None
    # __init__

    def build_gui(self):
        # create box for content
        self.main_box = toga.Box(style=Pack(direction=COLUMN, padding=5))
        
        if G.get_platform() == "win32":
            # adding commands
            self.app.commands = toga.CommandSet(
                self.app.factory
            )  # replaces the default CommandSet
            # is there a better way to get rid of the default menu ?
            # File > Preferences, Exit
            # Help > About, Homepage
            # add actions
            grpFile = toga.Group(label="File", order=1)
            # add actions
            cmdExit = toga.Command(
                lambda s: self.app.exit(),
                label="Exit",
                group=grpFile,
                section=sys.maxsize,
            )
            self.app.commands.add(cmdExit)

            grpHelp = toga.Group(label="Help", order=3)
            cmdAbout = toga.Command(
                self.handle_commands, label="About", group=grpHelp, order=1
            )
            cmdAbout.id = "cmdAbout"
            self.app.commands.add(cmdAbout)
            cmdHelp = toga.Command(
                self.handle_commands, label="Help", group=grpHelp, order=2
            )
            cmdHelp.id = "cmdHelp"
            self.app.commands.add(cmdHelp)
            cmdDebug = toga.Command(
                self.handle_commands, label="Show debug messages", group=grpHelp, order=3
            )
            cmdDebug.id = "cmdDebug"
            self.app.commands.add(cmdDebug)
        # win32

        if G.get_platform() == "android":
            # Menu
            self.app.commands = toga.CommandSet(
                self.app.factory
            )  # replaces the default CommandSet
            cmdAbout = toga.Command(
                self.handle_commands,
                label="About",
                group=toga.Group.COMMANDS,
                order=10,
            )
            cmdAbout.id = "cmdAbout"
            self.app.commands.add(cmdAbout)
            cmdHelp = toga.Command(
                self.handle_commands,
                label="Help",
                group=toga.Group.COMMANDS,
                order=20,
            )
            cmdHelp.id = "cmdHelp"
            self.app.commands.add(cmdHelp)
            cmdDebug = toga.Command(
                self.handle_commands,
                label="Show debug messages",
                group=toga.Group.COMMANDS,
                order=40,
            )
            cmdDebug.id = "cmdDebug"
            self.app.commands.add(cmdDebug)

        # add content to main_box
        self.main_box.add(toga.Label("Test App for spectre", style=Pack(flex=1, font_size=18)))
        self.type_box = toga.Box(style=Pack(direction=ROW, padding=5))
        self.type_box.add(toga.Label("Result Type", style=Pack(flex=1)))
        rtypes = spectreTypes.resultType.keys()
        self.rtypesel = toga.Selection(items=rtypes, style=Pack(flex=1))
        self.rtypesel.value = "templateLong"
        self.type_box.add(self.rtypesel)
        self.main_box.add(self.type_box)
        
        self.algo_box = toga.Box(style=Pack(direction=ROW, padding=5))
        self.algo_box.add(toga.Label("Algorithm Version", style=Pack(flex=1)))
        versions = ["0","1","2","3"]
        self.algosel = toga.Selection(items=versions, style=Pack(flex=1))
        self.algosel.value = str(spectreTypes.algorithm["current"])
        self.algo_box.add(self.algosel)
        self.main_box.add(self.algo_box)

        self.main_box.add(toga.Label("Your name", style=Pack(flex=1)))
        self.ti_name = toga.TextInput(style=Pack(flex=1))
        self.ti_name.value = "Tom"
        self.main_box.add(self.ti_name)
        
        self.main_box.add(toga.Label("Master password", style=Pack(flex=1)))
        self.ti_masterpw = toga.TextInput(style=Pack(flex=1))
        self.ti_masterpw.value = "test"
        self.main_box.add(self.ti_masterpw)
        
        self.main_box.add(toga.Label("Site", style=Pack(flex=1)))
        self.ti_site = toga.TextInput(style=Pack(flex=1))
        self.ti_site.value = "test.ch"
        self.main_box.add(self.ti_site)
        
        self.main_box.add(toga.Label("Site password", style=Pack(flex=1)))
        self.lbl_sitepw = toga.Label("", style=Pack(flex=1, font_size=18))
        self.main_box.add(self.lbl_sitepw)

        self.lbl_identicon = toga.Label("", style=Pack(flex=1, font_size=18))
        self.main_box.add(self.lbl_identicon)

        self.message_area = toga.MultilineTextInput(
            initial="", readonly=True, style=Pack(flex=1, font_size=18)
        )
        self.main_box.add(self.message_area)
        # Button bar
        _button_box = toga.Box(style=Pack(direction=ROW))
        _button_box.add(toga.Label("", style=Pack(flex=1)))
        _button_box.add(toga.Button("Generate", on_press=self.handle_btn_generate))
        _button_box.add(toga.Button("Clear", on_press=self.handle_btn_clear))
        _button_box.add(toga.Label("", style=Pack(flex=1)))
        self.main_box.add(_button_box)
    # build_gui

    def handle_btn_clear(self, widget):
        self.message_area.clear()
    # handle_btn_clear

    def handle_btn_generate(self, widget):
        try:
            self.fnPrintln("Generating...")
            rtype = self.rtypesel.value
            algover = int(self.algosel.value)
            userKey = spectre.newUserKey(self.ti_name.value, self.ti_masterpw.value, algover)
            # self.fnPrintln(str(userKey))
            # siteKey = spectre.newSiteKey(userKey, self.ti_site.value)
            # self.fnPrintln(str(siteKey))
            # self.fnPrintln(str(list(siteKey["keyData"])))
            sitepw = spectre.newSiteResult(userKey, self.ti_site.value, resultType=spectreTypes.resultType[rtype])
            # self.fnPrintln(f"Site password: {sitepw}")
            icon = spectre.newIdenticon(self.ti_name.value, self.ti_masterpw.value)
            icstr = icon["leftArm"]
            icstr += icon["body"]
            icstr += icon["rightArm"]
            icstr += icon["accessory"] + "   "
            icstr += icon["color"] + "       "
            # self.fnPrintln(icstr)
            self.lbl_sitepw.text = sitepw
            self.lbl_identicon.text = icstr
            self.fnPrintln("Done")
        except KeyError as ex:
           fnPrintln("\n"+str(ex))
           G.write_debug_message(str(ex))
        except Exception as ex:
           fnPrintln("\n"+str(ex))
           G.write_debug_message(str(ex))
    # handle_btn_generate


    def fnPrint(self, message):
        self.message_area.value += message
    # fnPrint
    
    def fnPrintln(self, message):
        self.fnPrint(message + "\n")
    # fnPrintln

    def handle_commands(self, widget):
        if widget.id == "cmdAbout":
            mygui = AboutGui(self.app, self, "< About", size=(400, 300))
            return mygui.show()
        if widget.id == "cmdHelp":
            mygui = HelpGui(self.app, self, "< Help",
                size=(int(self.window.size[0]*0.9), int(self.window.size[1]*0.9))
            )
            return mygui.show()
        if widget.id == "cmdDebug":
            return G.show_debug_messages()
    # handle_commands

    # @override
    def restore_state(self):
        """ 
        This method is called after app restarted due to device rotation
        """
        if len(self._state_data) > 0:
            G.write_debug_message("Restoring app state")
            self.message_area.value = self._state_data["message_area"]
            G.write_debug_message(G.get_debug_messages() + "\n" + self._state_data["debug_messages"])
    # restore_state

    # @override
    def save_state(self):
        """ 
        This method is called before app restarts when device rotation occurs
        All data saved to self._state_data is passed to the app on restart.
        """
        G.write_debug_message("Saving app state")
        self._state_data["message_area"] = self.message_area.value
        self._state_data["debug_messages"] = G.get_debug_messages()
    # save_state
# MainGui


class AboutGui(TaGui):
    window = None
    main_box = None
    message_area = None

    def __init__(self, app, parentGui, title, **kwargs):
        super().__init__(app, parentGui, title, **kwargs)
    # __init__

    def build_gui(self):
        # create box for content
        self.main_box = toga.Box(style=Pack(direction=COLUMN))
        msg =  "Python Playground {}\n\n".format(G.objApp.version)
        
        msg += "Freeware, (C) 2022 tanapro.ch\n\n"
        
        msg += "This app is a playground for Python developers who want to try Python "
        msg += "and Toga (www.beeware.org) without the need to set up a development environment "
        msg += "on the desktop with the complete toolchain.\n\n"

        msg += "To get started, read the help page of this app\n\n"
        
        msg += "The privacy policy can be found at\n"
        msg += "https://www.tanapro.ch/products/PrivacyPolicy/pyPlayground.html\n\n\n"
        
        if G.get_platform() == "android":
            msg += "\nPlatform: " + G.get_platform()
            vp = G.objMainGui.main_box._impl.container.viewport
            scale = float(vp.dpi) / vp.baseline_dpi
            msg += "\nViewport size in px: ({}, {})".format(vp.width, vp.height)
            msg += "\nViewport size in dp: ({}, {})".format(int(float(vp.width) / scale), int(float(vp.height) / scale))
            msg += "\nDensityDPI: " + str(vp.dpi)
            msg += "\nScaling factor: " + str(scale)

        self.message_area = toga.MultilineTextInput(
            initial=msg, readonly=True, style=Pack(flex=1)
        )
        self.main_box.add(self.message_area)
        
        # button bar
        _button_box = toga.Box(style=Pack(direction=ROW, padding=(5, 0, 0, 0)))  # top, right, bottom and left padding
        _button_box.add(toga.Label("", style=Pack(flex=1)))
        _button_box.add(toga.Button("OK", on_press=self.handle_btn_ok))
        _button_box.add(toga.Label("", style=Pack(flex=1)))
        self.main_box.add(_button_box)
    # build_gui
    
    def handle_btn_ok(self, widget):
        self.close()
    # handle_OK_button
# AboutGui


class HelpGui(TaGui):
    window = None
    main_box = None
    _webView = None
    _html_text = None

    def __init__(self, app, parentGui, title, **kwargs):
        super().__init__(app, parentGui, title, **kwargs)
    # __init__

    def build_gui(self):
        # create box for content
        self.main_box = toga.Box(style=Pack(direction=COLUMN))
        # read help file
        _helpfile = "{0}/resources/help-en.html".format(G.programDir)
        _helpfile = _helpfile.replace("\\", "/")
        _f = open(_helpfile, "r", encoding="utf-8")
        _text = _f.read()
        _f.close()
        _text = _text.replace("{app_data_dir}", str(G.get_data_path()))
        self._webView = toga.WebView(style=Pack(flex=1))
        self._webView.set_content("data:text/html,", _text)
        self.main_box.add(self._webView)

        # button bar
        _button_box = toga.Box(
            style=Pack(direction=ROW, padding=(5, 0, 0, 0))
        )  # top, right, bottom and left padding
        _button_box.add(toga.Label("", style=Pack(flex=1)))
        _button_box.add(toga.Button("OK", on_press=self.handle_btn_ok))
        _button_box.add(toga.Label("", style=Pack(flex=1)))
        self.main_box.add(_button_box)
    # build_gui

    def handle_btn_ok(self, widget):
        self.close()
    # handle_btn_ok
# HelpGui
