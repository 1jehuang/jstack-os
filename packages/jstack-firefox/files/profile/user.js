// jstack OS Firefox defaults. Copied to each new user's profile via /etc/skel.
// Theme: OLED black (pairs with chrome/userChrome.css). New tab and home are blank.
// Telemetry and first-run pages are off. Alt+<letter> menubar accelerators are
// disabled so Alt-based compositor binds reach niri.

user_pref("browser.link.open_newwindow", 2);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.tabs.warnOnClose", false);
user_pref("browser.tabs.warnOnOpen", false);
user_pref("browser.startup.page", 1);
user_pref("startup.homepage_welcome_url", "about:blank");
user_pref("network.http.max-connections-per-server", 10);
user_pref("toolkit.telemetry.enabled", false);
user_pref("extensions.activeThemeID", "firefox-compact-dark@mozilla.org");
user_pref("widget.content.allow-gtk-dark-theme", false);
user_pref("widget.non-native-theme.enabled", true);
user_pref("layout.css.prefers-color-scheme.content-override", 0);
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtabpage.url", "about:blank");
user_pref("browser.newtab.url", "about:blank");
user_pref("browser.newtab.extensionControlled", false);
user_pref("browser.newtabpage.activity-stream.enabled", false);
user_pref("browser.newtabpage.activity-stream.default.sites", "");
user_pref("browser.toolbars.bookmarks.visibility", "never");
user_pref("browser.newtabpage.activity-stream.feeds.section.highlights", false);
user_pref("browser.newtabpage.activity-stream.showRecentActivity", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeVisited", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeBookmarks", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeDownloads", false);
user_pref("browser.newtabpage.activity-stream.improvesearch.handoffToAwesomebar", false);
user_pref("browser.tabs.firefox-view", false);
user_pref("browser.tabs.firefox-view-next", false);
user_pref("browser.tabs.firefox-view-newIcon", false);
user_pref("browser.tabs.tabmanager.enabled", false);
user_pref("ui.key.menuAccessKeyFocuses", false);
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("startup.homepage_override_url", "");
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.messaging-system.whatsNewPanel.enabled", false);
user_pref("browser.uitour.enabled", false);
user_pref("browser.display.background_color", "#000000");
user_pref("browser.display.use_system_colors", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("devtools.browserconsole.contentMessages", true);
user_pref("devtools.chrome.enabled", true);
user_pref("datareporting.policy.firstRunURL", "");
user_pref("media.webrtc.camera.allow-pipewire", false);
user_pref("widget.use-xdg-desktop-portal.file-picker", 1);

user_pref("ui.key.menuAccessKey", 0);
