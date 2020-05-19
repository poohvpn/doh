package doh

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookup(t *testing.T) {
	is := assert.New(t)

	a, err := LookupA(`dohtest.poohvpn.com`)
	is.NoError(err)
	is.Len(a, 1)
	is.Equal(net.IPv4(2, 2, 2, 2), a[0])

	aaaa, err := LookupAAAA(`dohtest.poohvpn.com`)
	is.NoError(err)
	is.Len(aaaa, 1)
	is.Equal(net.IP{0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, aaaa[0])

	aAnaAAAA, err := LookupIP(`dohtest.poohvpn.com`)
	is.NoError(err)
	is.Len(aAnaAAAA, 2)
	is.ElementsMatch([]net.IP{net.IPv4(2, 2, 2, 2), {0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}, aAnaAAAA)

	txt, err := LookupTXT(`dohtest.poohvpn.com`)
	is.NoError(err)
	is.Len(txt, 1)
	is.Equal(`dohtest`, txt[0])

	cn, err := LookupCNAME(`cname.dohtest.poohvpn.com`)
	is.NoError(err)
	is.Equal(`dohtest`, cn)
}
