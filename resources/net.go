// Mgmt
// Copyright (C) 2013-2016+ James Shubin and the project contributors
// Written by James Shubin <james@shubin.ca> and the project contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// This resource controls the systemd-networkd configuration
// Configuration files have to be created in the local administration network
// directory /etc/systemd/network. Networks are configured in .network files, and
// virtual network devices are configured in .netdev files.
// Configuration files are sorted and processed in lexical order by
// the networkd service on startup.

// The resource will describe and enforce one or more network configurations.
// Each configuration ends up in a file:
//     /etc/systemd/network/<CONFIG_NAME>.network
//     e.g. /etc/systemd/network/10-static_ip.network

// The resource will:
// 1. Parse user defined network config into NetRes struct
// 2. Parse existing config files to NetRes struct, one per match
// 3. Compare existing with intended
// 4. Enforce config based on state

package resources

import (
	"encoding/gob"
	"log"
	"time"

	"github.com/purpleidea/mgmt/event"
	"github.com/purpleidea/mgmt/recwatch"
	"github.com/purpleidea/mgmt/util"

	errwrap "github.com/pkg/errors"
)

func init() {
	gob.Register(&NetRes{})
}

// Sections in .network files

// The match section provides a way to match an interface on which to set settings
type MatchSection struct {
	MACAddress        *string  `yaml:"mac_address"`         // The hardware address of the interface e.g., 01:23:45:67:89:ab
	Path              []string `yaml:"path"`                // Globs matching the persistent path, as exposed by the udev property "ID_PATH".
	Driver            []string `yaml:"driver"`              // Globs matching the driver currently bound to the device, as exposed by the udev property "DRIVER" of its parent device, or as exposed by "ethtool -i" of the device itself.
	Type              []string `yaml:"type"`                // Globs matching the device type, as exposed by the udev property "DEVTYPE".
	Name              []string `yaml:"name"`                // Globs matching the device name, as exposed by the udev property "INTERFACE".
	Host              *string  `yaml:"host"`                // Glob matching hostname or machine ID of the host. See "ConditionHost=" in systemd.unit(5) for details.
	Virtualization    *string  `yaml:"virtualization"`      // Checks whether the system is executed in a virtualized environment and optionally test whether it is a specific implementation. See "ConditionVirtualization=" in systemd.unit(5) for details.
	KernelCommandLine *string  `yaml:"kernel_command_line"` // Checks whether a specific kernel command line option is set. See "ConditionKernelCommandLine=" in systemd.unit(5) for details.
	Architecture      *string  `yaml:"architecture"`        // Checks whether the system is running on a specific architecture. See "ConditionArchitecture=" in systemd.unit(5) for details.
}

// The network section describes network settings
type NetworkSection struct {
	Description                   *string  `yaml:"description"`                      // A description of the device.
	DHCP                          *string  `yaml:"dhcp"`                             // Enables DHCPv4 and/or DHCPv6 client support. Accepts "yes", "no", "ipv4", or "ipv6".
	DHCPServer                    *bool    `yaml:"dhcp_server"`                      // Enables DHCPv4 server support. Defaults to false.
	LinkLocalAddressing           *string  `yaml:"link_local_addressing"`            // Enables link-local address autoconfiguration. Accepts "yes", "no", "ipv4", or "ipv6". Defaults to "ipv6".
	IPV4LLRoute                   *bool    `yaml:"ipv4_ll_route"`                    // When true, sets up the route needed for non-IPv4LL hosts to communicate with IPv4LL-only hosts. Defaults to false.
	IPV6Token                     *string  `yaml:"ipv6_token"`                       // An IPv6 address with the top 64 bits unset. When set, indicates the 64-bit interface part of SLAAC IPv6 addresses for this link.
	LLMNR                         *string  `yaml:"llmnr"`                            // A boolean or "resolve".
	MulticastDNS                  *string  `yaml:"multicast_dns"`                    // A boolean or "resolve".
	DNSSEC                        *string  `yaml:"dnssec"`                           // A boolean or "allow-downgrade".
	DNSSECNegativeTrustAnchors    []string `yaml:"dnssec_negative_trust_anchors"`    // DNSSEC negative trust anchor domains.
	LLDP                          *string  `yaml:"lldp"`                             // A boolean or "routers-only". When true, incoming LLDP packets
	EmitLLDP                      *string  `yaml:"emit_lldp"`                        // A boolean  or the special values "nearest-bridge", "non-tpmr-bridge" and "customer-bridge". Defaults to false.
	BindCarrier                   []string `yaml:"bind_carrier"`                     // A link name or a list of link names.
	Address                       []string `yaml:"address"`                          // A static IPv4 or IPv6 address and its prefix length, separated by a "/" character. Specify this key more than once to configure several addresses.
	Gateway                       []string `yaml:"gateway"`                          // Gateway addresses, which must be in the format described in inet_pton(3).
	DNS                           []string `yaml:"dns"`                              // DNS server addresses, which must be in the format described in
	Domains                       []string `yaml:"domains"`                          // A list of domains which should be resolved using the DNS servers on this link.
	NTP                           []string `yaml:"ntp"`                              // NTP server addresses.
	IPForward                     *string  `yaml:"ip_forward"`                       // A boolean or "ipv4" or "ipv6". Defaults to false.
	IPMasquerade                  *bool    `yaml:"ip_masquerade"`                    // Configures IP masquerading for the network interface. Defaults to false.
	IPV6PrivacyExtensions         *bool    `yaml:"ipv6_privacy_extensions"`          // A boolean or the special values "prefer-public" and "kernel". Defaults to false.
	IPV6AcceptRA                  *bool    `yaml:"ipv6_accept_ra"`                   // Enable or disable IPv6 Router Advertisement (RA) reception support on the interface.
	IPV6DuplicateAddressDetection *int     `yaml:"ipv6_duplicate_address_detection"` // Configures the amount of IPv6 Duplicate Address Detection (DAD) probes to send. Defaults to unset.
	IPV6HopLimit                  *int     `yaml:"ipv6_hop_limit"`                   // Configures IPv6 Hop Limit. Defaults to unset.
	ProxyARP                      *bool    `yaml:"proxy_arp"`                        // Configures proxy ARP. Defaults to unset.
	Bridge                        *string  `yaml:"bridge"`                           // The name of the bridge to add the link to.
	Bond                          *string  `yaml:"bond"`                             // The name of the bond to add the link to.
	VRF                           *string  `yaml:"vrf"`                              // The name of the VRF to add the link to.
	VLAN                          []string `yaml:"vlan"`                             // The names of the VLANs to create on the link.
	MACVLAN                       []string `yaml:"macvlan"`                          // The names of the MACVLANs to create on the link.
	VXLAN                         []string `yaml:"vxlan"`                            // The names of the VXLANs to create on the link.
	Tunnel                        []string `yaml:"tunnel"`                           // The names of the Tunnels to create on the link.
}

type LinkSection struct {
}

type AddressSection struct {
}

type RouteSection struct {
}

type DHCPSection struct {
}

type IPv6Section struct {
}

type DHCPServerSection struct {
}

type BridgeSection struct {
}

type BridgeFDBSection struct {
}

type BridgeVLANSection struct {
}

// NetRes is a systemd-networkd resource.
type NetRes struct {
	BaseRes    `yaml:",inline"`
	Match      MatchSection         `yaml:"match"`
	Link       LinkSection          `yaml:"link"`
	Address    AddressSection       `yaml:"address"`
	Route      RouteSection         `yaml:"route"`
	DHCP       DHCPSection          `yaml:"dhcp"`
	IPv6       IPv6Section          `yaml:"ipv6"`
	DHCPServer DHCPServerSection    `yaml:"dhcp_server"`
	Bridge     BridgeSection        `yaml:"bridge"`
	BridgeFDB  BridgeFDBSection     `yaml:"bridge_fdb"`
	BridgeVLAN BridgeVLANSection    `yaml:"bridge_vlan"`
	State      string               `yaml:"state"` // state: exists/present?, absent, (undefined?)
	Force      bool                 `yaml:"force"`
	configDir  string               // dir containing networkd config files (/etc/systemd/network/)
	path       string               // path to .network config file
	recWatcher *recwatch.RecWatcher // watcher for config files
}

// NewNetRes is a constructor for this resource. It also calls Init() for you.
func NewNetRes(name, path, dirname, basename string, content *string, source, state string, recurse, force bool) (*NetRes, error) {
	obj := &NetRes{
		BaseRes: BaseRes{
			Name: name,
		},
		State: state,
		Force: force,
	}
	return obj, obj.Init()
}

// Init runs some startup code for this resource.
func (obj *NetRes) Init() error {
	obj.configDir = "/etc/systemd/network/"
	obj.path = obj.configDir + "/" + obj.Name + ".network"

	obj.BaseRes.kind = "Net"
	return obj.BaseRes.Init() // call base init, b/c we're overriding
}

// Validate reports any problems with the struct definition.
// Check for invalid IPs, MACs, CIDRs ++
func (obj *NetRes) Validate() error {
	return nil
}

// Watch is the primary listener for this resource and it outputs events.
// This one is a file watcher for netword config files.
// If the Watch returns an error, it means that something has gone wrong, and it
// must be restarted. On a clean exit it returns nil.
func (obj *NetRes) Watch(processChan chan event.Event) error {
	if obj.IsWatching() {
		return nil // TODO: should this be an error?
	}
	obj.SetWatching(true)
	defer obj.SetWatching(false)
	cuid := obj.converger.Register()
	defer cuid.Unregister()

	var startup bool
	Startup := func(block bool) <-chan time.Time {
		if block {
			return nil // blocks forever
			//return make(chan time.Time) // blocks forever
		}
		return time.After(time.Duration(500) * time.Millisecond) // 1/2 the resolution of converged timeout
	}

	var err error
	obj.recWatcher, err = recwatch.NewRecWatcher(obj.path, false)
	if err != nil {
		return err
	}
	defer obj.recWatcher.Close()

	var send = false // send event?
	var exit = false
	var dirty = false

	for {
		if obj.debug {
			log.Printf("%s[%s]: Watching: %s", obj.Kind(), obj.GetName(), obj.path) // attempting to watch...
		}

		obj.SetState(ResStateWatching) // reset
		select {
		case event, ok := <-obj.recWatcher.Events():
			if !ok { // channel shutdown
				return nil
			}
			cuid.SetConverged(false)
			if err := event.Error; err != nil {
				return errwrap.Wrapf(err, "Unknown %s[%s] watcher error", obj.Kind(), obj.GetName())
			}
			if obj.debug { // don't access event.Body if event.Error isn't nil
				log.Printf("%s[%s]: Event(%s): %v", obj.Kind(), obj.GetName(), event.Body.Name, event.Body.Op)
			}
			send = true
			dirty = true

		case event := <-obj.Events():
			cuid.SetConverged(false)
			if exit, send = obj.ReadEvent(&event); exit {
				return nil // exit
			}
			//dirty = false // these events don't invalidate state

		case <-cuid.ConvergedTimer():
			cuid.SetConverged(true) // converged!
			continue

		case <-Startup(startup):
			cuid.SetConverged(false)
			send = true
			dirty = true
		}

		// do all our event sending all together to avoid duplicate msgs
		if send {
			startup = true // startup finished
			send = false
			// only invalid state on certain types of events
			if dirty {
				dirty = false
				obj.isStateOK = false // something made state dirty
			}
			if exit, err := obj.DoSend(processChan, ""); exit || err != nil {
				return err // we exit or bubble up a NACK...
			}
		}
	}
}

// CheckApply checks the resource state and applies the resource if the bool
// input is true. It returns error info and if the state check passed or not.
func (obj *NetRes) CheckApply(apply bool) (checkOK bool, _ error) {
	log.Printf("%s[%s]: CheckApply(%t)", obj.Kind(), obj.GetName(), apply)

	if obj.isStateOK { // cache the state
		return true, nil
	}

	checkOK = true

	// if we did work successfully, or are in a good state, then state is ok
	if apply || checkOK {
		obj.isStateOK = true
	}
	return checkOK, nil // w00t
}

// FileUID is the UID struct for NetRes.
type NetUID struct {
	BaseUID
	path string
}

// IFF aka if and only if they are equivalent, return true. If not, false.
func (obj *NetUID) IFF(uid ResUID) bool {
	res, ok := uid.(*NetUID)
	if !ok {
		return false
	}
	return obj.path == res.path
}

// NetResAutoEdges holds the state of the auto edge generator.
type NetResAutoEdges struct {
	data    []ResUID
	pointer int
	found   bool
}

// Next returns the next automatic edge.
func (obj *NetResAutoEdges) Next() []ResUID {
	if obj.found {
		log.Fatal("Shouldn't be called anymore!")
	}
	if len(obj.data) == 0 { // check length for rare scenarios
		return nil
	}
	value := obj.data[obj.pointer]
	obj.pointer++
	return []ResUID{value} // we return one, even though api supports N
}

// Test gets results of the earlier Next() call, & returns if we should continue!
func (obj *NetResAutoEdges) Test(input []bool) bool {
	// if there aren't any more remaining
	if len(obj.data) <= obj.pointer {
		return false
	}
	if obj.found { // already found, done!
		return false
	}
	if len(input) != 1 { // in case we get given bad data
		log.Fatal("Expecting a single value!")
	}
	if input[0] { // if a match is found, we're done!
		obj.found = true // no more to find!
		return false
	}
	return true // keep going
}

// AutoEdges generates a simple linear sequence of each parent directory from
// the bottom up!
func (obj *NetRes) AutoEdges() AutoEdge {
	var data []ResUID                              // store linear result chain here...
	values := util.PathSplitFullReversed(obj.path) // build it
	_, values = values[0], values[1:]              // get rid of first value which is me!
	for _, x := range values {
		var reversed = true // cheat by passing a pointer
		data = append(data, &FileUID{
			BaseUID: BaseUID{
				name:     obj.GetName(),
				kind:     obj.Kind(),
				reversed: &reversed,
			},
			path: x, // what matters
		}) // build list
	}
	return &NetResAutoEdges{
		data:    data,
		pointer: 0,
		found:   false,
	}
}

// GetUIDs includes all params to make a unique identification of this object.
// Most resources only return one, although some resources can return multiple.
func (obj *NetRes) GetUIDs() []ResUID {
	x := &FileUID{
		BaseUID: BaseUID{name: obj.GetName(), kind: obj.Kind()},
		path:    obj.path,
	}
	return []ResUID{x}
}

// GroupCmp returns whether two resources can be grouped together or not.
func (obj *NetRes) GroupCmp(r Res) bool {
	_, ok := r.(*NetRes)
	if !ok {
		return false
	}
	// TODO: we might be able to group directory children into a single
	// recursive watcher in the future, thus saving fanotify watches
	return false // not possible atm
}

// Compare two resources and return if they are equivalent.
func (obj *NetRes) Compare(res Res) bool {
	switch res.(type) {
	case *NetRes:
		res := res.(*NetRes)
		if !obj.BaseRes.Compare(res) { // call base Compare
			return false
		}

		if obj.Name != res.Name {
			return false
		}

		// Check all sections for equality
		/*
		  Match      MatchSection      `yaml:"match"`
		  Link       LinkSection       `yaml:"link"`
		  Address    AddressSection    `yaml:"address"`
		  Route      RouteSection      `yaml:"route"`
		  DHCP       DHCPSection       `yaml:"dhcp"`
		  IPv6       IPv6Section       `yaml:"ipv6"`
		  DHCPServer DHCPServerSection `yaml:"dhcp_server"`
		  Bridge     BridgeSection     `yaml:"bridge"`
		  BridgeFDB  BridgeFDBSection  `yaml:"bridge_fdb"`
		  BridgeVLAN BridgeVLANSection `yaml:"bridge_vlan"`
		*/

		if obj.Force != res.Force {
			return false
		}
	default:
		return false
	}
	return true
}
