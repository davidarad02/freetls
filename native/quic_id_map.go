package main

import quic "github.com/refraction-networking/uquic"

// quicIDNames lists the built-in uQUIC QUICIDs, in a stable order. The aliases
// uQUIC defines (QUICFirefox_116, QUICChrome_115, QUICChrome_146) are included
// and resolve to their most common variant.
var quicIDNames = []string{
	"QUICFirefox_116",
	"QUICFirefox_116A",
	"QUICFirefox_116B",
	"QUICFirefox_116C",
	"QUICChrome_115",
	"QUICChrome_115_IPv4",
	"QUICChrome_115_IPv6",
	"QUICChrome_146",
	"QUICChrome_146_IPv4",
	"QUICChrome_146_IPv6",
}

// quicIDByName maps a preset name to its uQUIC QUICID. Keep in sync with
// quicIDNames; uQUIC ships no registry of its own, so this is maintained by hand
// (there are few entries, and new ones are added upstream behind a TODO).
var quicIDByName = map[string]quic.QUICID{
	"QUICFirefox_116":       quic.QUICFirefox_116,
	"QUICFirefox_116A":      quic.QUICFirefox_116A,
	"QUICFirefox_116B":      quic.QUICFirefox_116B,
	"QUICFirefox_116C":      quic.QUICFirefox_116C,
	"QUICChrome_115":        quic.QUICChrome_115,
	"QUICChrome_115_IPv4":   quic.QUICChrome_115_IPv4,
	"QUICChrome_115_IPv6":   quic.QUICChrome_115_IPv6,
	"QUICChrome_146":        quic.QUICChrome_146,
	"QUICChrome_146_IPv4":   quic.QUICChrome_146_IPv4,
	"QUICChrome_146_IPv6":   quic.QUICChrome_146_IPv6,
}
