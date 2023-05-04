//my settings
//Offline website data off
user_pref("privacy.item.offlineApps", false);

//New tab auto open
user_pref("browser.tabs.loadInBackground", false);
user_pref("browser.tabs.loadDivertedInBackground", true);
user_pref("browser.tabs.loadBookmarksInBackground", true);

//always show bookmark tab
user_pref("browser.toolbars.bookmarks.visibility", "always");

//dont ask password
user_pref("signon.rememberSignons", false);

//show http:// - https://
user_pref("browser.urlbar.trimURLs", false);

// sync firefox account
user_pref("identity.fxaccounts.enabled", false); 

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

//enable auto play videos
user_pref("media.autoplay.default", 0);
