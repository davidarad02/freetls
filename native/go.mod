module github.com/freetls/native

go 1.27.0

require (
	github.com/refraction-networking/uquic v0.0.0-20260804184259-837c7ce1b72b
	github.com/refraction-networking/utls v1.8.3-0.20261006195536-6ebdceb2607e
	golang.org/x/net v0.43.0
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/clienthellod v0.5.0-alpha2 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)

replace github.com/refraction-networking/utls => ./third_party/utls

replace github.com/refraction-networking/uquic => ./third_party/uquic
