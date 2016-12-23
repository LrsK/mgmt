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
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
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

// The [MATCH] section provides a way to match an interface on which to
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
	State      string            `yaml:"state"` // state: exists/present?, absent, (undefined?)
	Force      bool              `yaml:"force"`
	configDir  string            // dir containing networkd config files (/etc/systemd/network/)
	path       string            // path to .network config file
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
// This one is a file watcher for files and directories.
// Modify with caution, it is probably important to write some test cases first!
// If the Watch returns an error, it means that something has gone wrong, and it
// must be restarted. On a clean exit it returns nil.
// FIXME: Also watch the source directory when using obj.Source !!!
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
	obj.recWatcher, err = recwatch.NewRecWatcher(obj.Path, obj.Recurse)
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

// fileCheckApply is the CheckApply operation for a source and destination file.
// It can accept an io.Reader as the source, which can be a regular file, or it
// can be a bytes Buffer struct. It can take an input sha256 hash to use instead
// of computing the source data hash, and it returns the computed value if this
// function reaches that stage. As usual, it respects the apply action variable,
// and it symmetry with the main CheckApply function returns checkOK and error.
func (obj *NetRes) fileCheckApply(apply bool, src io.ReadSeeker, dst string, sha256sum string) (string, bool, error) {
	// TODO: does it make sense to switch dst to an io.Writer ?
	// TODO: use obj.Force when dealing with symlinks and other file types!
	if obj.debug {
		log.Printf("fileCheckApply: %s -> %s", src, dst)
	}

	srcFile, isFile := src.(*os.File)
	_, isBytes := src.(*bytes.Reader) // supports seeking!
	if !isFile && !isBytes {
		return "", false, fmt.Errorf("Can't open src as either file or buffer!")
	}

	var srcStat os.FileInfo
	if isFile {
		var err error
		srcStat, err = srcFile.Stat()
		if err != nil {
			return "", false, err
		}
		// TODO: deal with symlinks
		if !srcStat.Mode().IsRegular() { // can't copy non-regular files or dirs
			return "", false, fmt.Errorf("Non-regular src file: %s (%q)", srcStat.Name(), srcStat.Mode())
		}
	}

	dstFile, err := os.Open(dst)
	if err != nil && !os.IsNotExist(err) { // ignore ErrNotExist errors
		return "", false, err
	}
	dstClose := func() error {
		return dstFile.Close() // calling this twice is safe :)
	}
	defer dstClose()
	dstExists := !os.IsNotExist(err)

	dstStat, err := dstFile.Stat()
	if err != nil && dstExists {
		return "", false, err
	}

	if dstExists && dstStat.IsDir() { // oops, dst is a dir, and we want a file...
		if !apply {
			return "", false, nil
		}
		if !obj.Force {
			return "", false, fmt.Errorf("Can't force dir into file: %s", dst)
		}

		cleanDst := path.Clean(dst)
		if cleanDst == "" || cleanDst == "/" {
			return "", false, fmt.Errorf("Don't want to remove root!") // safety
		}
		// FIXME: respect obj.Recurse here...
		// there is a dir here, where we want a file...
		log.Printf("fileCheckApply: Removing (force): %s", cleanDst)
		if err := os.RemoveAll(cleanDst); err != nil { // dangerous ;)
			return "", false, err
		}
		dstExists = false // now it's gone!

	} else if err == nil {
		if !dstStat.Mode().IsRegular() {
			return "", false, fmt.Errorf("Non-regular dst file: %s (%q)", dstStat.Name(), dstStat.Mode())
		}
		if isFile && os.SameFile(srcStat, dstStat) { // same inode, we're done!
			return "", true, nil
		}
	}

	if dstExists { // if dst doesn't exist, no need to compare hashes
		// hash comparison (efficient because we can cache hash of content str)
		if sha256sum == "" { // cache is invalid
			hash := sha256.New()
			// TODO: file existence test?
			if _, err := io.Copy(hash, src); err != nil {
				return "", false, err
			}
			sha256sum = hex.EncodeToString(hash.Sum(nil))
			// since we re-use this src handler below, it is
			// *critical* to seek to 0, or we'll copy nothing!
			if n, err := src.Seek(0, 0); err != nil || n != 0 {
				return sha256sum, false, err
			}
		}

		// dst hash
		hash := sha256.New()
		if _, err := io.Copy(hash, dstFile); err != nil {
			return "", false, err
		}
		if h := hex.EncodeToString(hash.Sum(nil)); h == sha256sum {
			return sha256sum, true, nil // same!
		}
	}

	// state is not okay, no work done, exit, but without error
	if !apply {
		return sha256sum, false, nil
	}
	if obj.debug {
		log.Printf("fileCheckApply: Apply: %s -> %s", src, dst)
	}

	dstClose() // unlock file usage so we can write to it
	dstFile, err = os.Create(dst)
	if err != nil {
		return sha256sum, false, err
	}
	defer dstFile.Close() // TODO: is this redundant because of the earlier defered Close() ?

	if isFile { // set mode because it's a new file
		if err := dstFile.Chmod(srcStat.Mode()); err != nil {
			return sha256sum, false, err
		}
	}

	// TODO: attempt to reflink with Splice() and int(file.Fd()) as input...
	// syscall.Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error)

	// TODO: should we offer a way to cancel the copy on ^C ?
	if obj.debug {
		log.Printf("fileCheckApply: Copy: %s -> %s", src, dst)
	}
	if n, err := io.Copy(dstFile, src); err != nil {
		return sha256sum, false, err
	} else if obj.debug {
		log.Printf("fileCheckApply: Copied: %v", n)
	}
	return sha256sum, false, dstFile.Sync()
}

// syncCheckApply is the CheckApply operation for a source and destination dir.
// It is recursive and can create directories directly, and files via the usual
// fileCheckApply method. It returns checkOK and error as is normally expected.
func (obj *NetRes) syncCheckApply(apply bool, src, dst string) (bool, error) {
	if obj.debug {
		log.Printf("syncCheckApply: %s -> %s", src, dst)
	}
	if src == "" || dst == "" {
		return false, fmt.Errorf("The src and dst must not be empty!")
	}

	var checkOK = true
	// TODO: handle ./ cases or ../ cases that need cleaning ?

	srcIsDir := strings.HasSuffix(src, "/")
	dstIsDir := strings.HasSuffix(dst, "/")

	if srcIsDir != dstIsDir {
		return false, fmt.Errorf("The src and dst must be both either files or directories.")
	}

	if !srcIsDir && !dstIsDir {
		if obj.debug {
			log.Printf("syncCheckApply: %s -> %s", src, dst)
		}
		fin, err := os.Open(src)
		if err != nil {
			if obj.debug && os.IsNotExist(err) { // if we get passed an empty src
				log.Printf("syncCheckApply: Missing src: %s", src)
			}
			return false, err
		}

		_, checkOK, err := obj.fileCheckApply(apply, fin, dst, "")
		if err != nil {
			fin.Close()
			return false, err
		}
		return checkOK, fin.Close()
	}

	// else: if srcIsDir && dstIsDir
	srcFiles, err := ReadDir(src)          // if src does not exist...
	if err != nil && !os.IsNotExist(err) { // an empty map comes out below!
		return false, err
	}
	dstFiles, err := ReadDir(dst)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	//log.Printf("syncCheckApply: srcFiles: %v", srcFiles)
	//log.Printf("syncCheckApply: dstFiles: %v", dstFiles)
	smartSrc := mapPaths(srcFiles)
	smartDst := mapPaths(dstFiles)

	for relPath, fileInfo := range smartSrc {
		absSrc := fileInfo.AbsPath // absolute path
		absDst := dst + relPath    // absolute dest

		if _, exists := smartDst[relPath]; !exists {
			if fileInfo.IsDir() {
				if !apply { // only checking and not identical!
					return false, nil
				}

				// file exists, but we want a dir: we need force
				// we check for the file w/o the smart dir slash
				relPathFile := strings.TrimSuffix(relPath, "/")
				if _, ok := smartDst[relPathFile]; ok {
					absCleanDst := path.Clean(absDst)
					if !obj.Force {
						return false, fmt.Errorf("Can't force file into dir: %s", absCleanDst)
					}
					if absCleanDst == "" || absCleanDst == "/" {
						return false, fmt.Errorf("Don't want to remove root!") // safety
					}
					log.Printf("syncCheckApply: Removing (force): %s", absCleanDst)
					if err := os.Remove(absCleanDst); err != nil {
						return false, err
					}
					delete(smartDst, relPathFile) // rm from purge list
				}

				if obj.debug {
					log.Printf("syncCheckApply: mkdir -m %s '%s'", fileInfo.Mode(), absDst)
				}
				if err := os.Mkdir(absDst, fileInfo.Mode()); err != nil {
					return false, err
				}
				checkOK = false // we did some work
			}
			// if we're a regular file, the recurse will create it
		}

		if obj.debug {
			log.Printf("syncCheckApply: Recurse: %s -> %s", absSrc, absDst)
		}
		if obj.Recurse {
			if c, err := obj.syncCheckApply(apply, absSrc, absDst); err != nil { // recurse
				return false, errwrap.Wrapf(err, "syncCheckApply: Recurse failed")
			} else if !c { // don't let subsequent passes make this true
				checkOK = false
			}
		}
		if !apply && !checkOK { // check failed, and no apply to do, so exit!
			return false, nil
		}
		delete(smartDst, relPath) // rm from purge list
	}

	if !apply && len(smartDst) > 0 { // we know there are files to remove!
		return false, nil // so just exit now
	}
	// any files that now remain in smartDst need to be removed...
	for relPath, fileInfo := range smartDst {
		absSrc := src + relPath    // absolute dest (should not exist!)
		absDst := fileInfo.AbsPath // absolute path (should get removed)
		absCleanDst := path.Clean(absDst)
		if absCleanDst == "" || absCleanDst == "/" {
			return false, fmt.Errorf("Don't want to remove root!") // safety
		}

		// FIXME: respect obj.Recurse here...

		// NOTE: we could use os.RemoveAll instead of recursing, but I
		// think the symmetry is more elegant and correct here for now
		// Avoiding this is also useful if we had a recurse limit arg!
		if true { // switch
			log.Printf("syncCheckApply: Removing: %s", absCleanDst)
			if apply {
				if err := os.RemoveAll(absCleanDst); err != nil { // dangerous ;)
					return false, err
				}
				checkOK = false
			}
			continue
		}
		_ = absSrc
		//log.Printf("syncCheckApply: Recurse rm: %s -> %s", absSrc, absDst)
		//if c, err := obj.syncCheckApply(apply, absSrc, absDst); err != nil {
		//	return false, errwrap.Wrapf(err, "syncCheckApply: Recurse rm failed")
		//} else if !c { // don't let subsequent passes make this true
		//	checkOK = false
		//}
		//log.Printf("syncCheckApply: Removing: %s", absCleanDst)
		//if apply { // safety
		//	if err := os.Remove(absCleanDst); err != nil {
		//		return false, err
		//	}
		//	checkOK = false
		//}
	}

	return checkOK, nil
}

// contentCheckApply performs a CheckApply for the file existence and content.
func (obj *NetRes) contentCheckApply(apply bool) (checkOK bool, _ error) {
	log.Printf("%s[%s]: contentCheckApply(%t)", obj.Kind(), obj.GetName(), apply)

	if obj.State == "absent" {
		if _, err := os.Stat(obj.path); os.IsNotExist(err) {
			// no such file or directory, but
			// file should be missing, phew :)
			return true, nil

		} else if err != nil { // what could this error be?
			return false, err
		}

		// state is not okay, no work done, exit, but without error
		if !apply {
			return false, nil
		}

		log.Printf("contentCheckApply: Removing: %s", obj.path)
		err := os.RemoveAll(obj.path)
		return false, err // either nil or not
	}

	// content is not defined, leave it alone...
	if obj.Content == nil {
		return true, nil
	}

	checkOK, err := obj.syncCheckApply(apply, obj.Source, obj.path)
	if err != nil {
		log.Printf("syncCheckApply: Error: %v", err)
		return false, err
	}

	return checkOK, nil
}

// CheckApply checks the resource state and applies the resource if the bool
// input is true. It returns error info and if the state check passed or not.
func (obj *NetRes) CheckApply(apply bool) (checkOK bool, _ error) {
	log.Printf("%s[%s]: CheckApply(%t)", obj.Kind(), obj.GetName(), apply)

	if obj.isStateOK { // cache the state
		return true, nil
	}

	checkOK = true

	// Check content
	if c, err := obj.contentCheckApply(apply); err != nil {
		return false, err
	} else if !c {
		checkOK = false
	}

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
		if obj.path != res.Path {
			return false
		}
		if (obj.Content == nil) != (res.Content == nil) { // xor
			return false
		}
		if obj.Content != nil && res.Content != nil {
			if *obj.Content != *res.Content { // compare the strings
				return false
			}
		}
		if obj.Source != res.Source {
			return false
		}
		if obj.State != res.State {
			return false
		}
		if obj.Recurse != res.Recurse {
			return false
		}
		if obj.Force != res.Force {
			return false
		}
	default:
		return false
	}
	return true
}

// CollectPattern applies the pattern for collection resources.
func (obj *NetRes) CollectPattern(pattern string) {
	// XXX: currently the pattern for files can only override the Dirname variable :P
	obj.Dirname = pattern // XXX: simplistic for now
}
