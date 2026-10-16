package main

// Blank imports so every engine build compiles and links the QUIC stack, even
// before the QUIC entrypoints are wired. A dependency or version problem then
// shows up as a build failure here rather than at first use at runtime.
import (
	_ "github.com/refraction-networking/uquic"
	_ "github.com/refraction-networking/uquic/http3"
)
