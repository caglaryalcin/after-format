//my settings
//Offline website data off
user_pref("privacy.item.offlineApps", false);

//New tab auto open
user_pref("browser.tabs.loadInBackground", true);
user_pref("browser.tabs.loadDivertedInBackground", true);
user_pref("browser.tabs.loadBookmarksInBackground", true);

//always show bookmark tab
user_pref("browser.toolbars.bookmarks.visibility", "always");

//dont ask password
user_pref("signon.rememberSignons", false);

//show http:// - https://
user_pref("browser.urlbar.trimURLs", false);

// sync firefox account
user_pref("identity.fxaccounts.enabled", true); 

//disable history cache
user_pref("privacy.clearOnShutdown.cookies", false);
user_pref("privacy.clearOnShutdown.cache", false);
user_pref("privacy.clearOnShutdown.history", false);
user_pref("privacy.sanitize.sanitizeOnShutdown", false);
user_pref("privacy.clearOnShutdown.offlineApps", false);
user_pref("privacy.clearOnShutdown.sessions", false);
user_pref("privacy.clearOnShutdown.siteSettings", false);
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");
user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");

//bitwarden size fix
user_pref("privacy.resistFingerprinting", false);

//disable notifications
user_pref("dom.webnotifications.enabled", false);

//disable compatibility checking for extensions
user_pref("extensions.checkCompatibility", false);

//disable animations
user_pref("browser.tabs.animate", false);
user_pref("browser.panorama.animate_zoom", false);
user_pref("browser.fullscreen.animateUp", false);
user_pref("toolkit.cosmeticAnimations.enabled", false);

//disable picture in picture-pop up
user_pref("extensions.pictureinpicture.enable_picture_in_picture_overrides", false);
user_pref("browser.download.alwaysOpenPanel", false);
user_pref("media.videocontrols.picture-in-picture.video-toggle.enabled", false);

//Close All Tabs But Do Not Close Firefox
user_pref("string.showQuitwarning", true);

//Open New Tab for the Search Box Results
user_pref("browser.search.openintab", true);
user_pref("browser.link.open_newwindow", 3);

//Lower Memory Usage When Minimized
user_pref("config.trim_on_minimize", true);

//Select All Text When You Click on the URL Bar
user_pref("browser.urlbar.clickSelectsAll", false);

//Extend Script Execution Time
user_pref("dom.max_script_run_time", 20);

//Configure Backspace Button
user_pref("browser.backspace_action", 1);

//Change Number of Suggestions in the Awesomebar Dropdown
user_pref("browser.urlbar.maxRichResults", 1);

//enable custom css
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
user_pref("layers.acceleration.force-enabled", false);
user_pref("gfx.webrender.all", false);
user_pref("svg.context-properties.content.enabled", false);

//enable auto play videos
user_pref("media.autoplay.default", 0);

//customization layout
user_pref("browser.uiCustomization.state", {"placements":{"widget-overflow-fixed-list":[],"unified-extensions-area":[],"nav-bar":["back-button","forward-button","stop-reload-button","urlbar-container","save-to-pocket-button","downloads-button","jid1-mnnxcxisbpnsxq_jetpack-browser-action","_446900e4-71c2-419f-a6a7-df9c091e268b_-browser-action","ublock0_raymondhill_net-browser-action","_ublacklist-browser-action","addon_darkreader_org-browser-action","skipredirect_sblask-browser-action","_762f9885-5a13-4abd-9c77-433dcd38b8fd_-browser-action","fxa-toolbar-menu-button","unified-extensions-button"],"toolbar-menubar":["menubar-items"],"TabsToolbar":["tabbrowser-tabs","new-tab-button","alltabs-button"],"PersonalToolbar":["personal-bookmarks"]},"seen":["_ublacklist-browser-action","addon_darkreader_org-browser-action","jid1-mnnxcxisbpnsxq_jetpack-browser-action","skipredirect_sblask-browser-action","ublock0_raymondhill_net-browser-action","_446900e4-71c2-419f-a6a7-df9c091e268b_-browser-action","_762f9885-5a13-4abd-9c77-433dcd38b8fd_-browser-action","developer-button"],"dirtyAreaCache":["unified-extensions-area","nav-bar","toolbar-menubar","TabsToolbar","PersonalToolbar"],"currentVersion":19,"newElementCount":5}

//disable pocket-button
user_pref("extensions.pocket.enabled", false);

//firefox 120hz
user_pref("layout.frame_rate", 144);

//Changing the default processor allocation from a maximum of 8 to 12
user_pref("dom.ipc.processCount", 12);

//top bar size
user_pref("layout.css.devPixelsPerPx", "1");

//disable multiple tabs before open warn
user_pref("browser.tabs.maxOpenBeforeWarn", 15);

//disable ssl require safe negotiation for pay sites
user_pref("security.ssl.require_safe_negotiation", false);

//disable reader view
user_pref("reader.parse-on-load.enabled", false);