// Hosted test manifest for the cfg80211 core.
//
// Every child is declared with its own explicit path. A bare `mod x;` inside a
// child of this file would bind to a sibling of THIS file, not to a file in
// `tests/`, and would silently compile the implementation instead of the test.

#[path = "tests/frames.rs"] mod frames;
#[path = "tests/elements.rs"] mod elements;
#[path = "tests/channels.rs"] mod channels;
#[path = "tests/regulatory.rs"] mod regulatory;
#[path = "tests/country.rs"] mod country;
#[path = "tests/bss_cache.rs"] mod bss_cache;
#[path = "tests/connect.rs"] mod connect;
#[path = "tests/keyring.rs"] mod keyring;
