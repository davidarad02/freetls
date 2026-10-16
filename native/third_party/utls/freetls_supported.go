package tls

// FreetlsSupportedCipherSuiteIDs returns the IDs of every cipher suite this
// build can actually complete: the native Go suites plus any registered by the
// freetls_libcrypto backend. It is used by the freetls safe-mode validator to
// reject specs whose offered ciphers the engine cannot finish.
//
// This file is part of the freetls fork (new file; upstream is never edited).
func FreetlsSupportedCipherSuiteIDs() []uint16 {
	ids := make([]uint16, 0, len(utlsSupportedCipherSuites)+len(cipherSuitesTLS13))
	seen := make(map[uint16]bool, cap(ids))
	add := func(id uint16) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, s := range utlsSupportedCipherSuites {
		add(s.id)
	}
	for _, s := range cipherSuitesTLS13 {
		add(s.id)
	}
	return ids
}
