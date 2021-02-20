package maid

import (
    "sync"
    "strconv"
    "strings"
    "gvisor.dev/gvisor/pkg/usermem"
    "gvisor.dev/gvisor/pkg/log"
)

// multiple address
type TargetAddrs struct {
        sync.Mutex
        Addrs map[usermem.Addr]int
}

func NewTargetAddrs() *TargetAddrs {
    maddr := new(TargetAddrs)
    maddr.Addrs = make(map[usermem.Addr]int)

    return maddr
}

// single address
type TargetAddr struct {
    sync.Mutex
    Addr usermem.Addr
    Flag bool
    SleepTime int
    WaitTime int
}

func NewTargetAddr() *TargetAddr {
    maddr := new(TargetAddr)
    return maddr
}

// storing the original perms of target addresses
type ModAddr struct {
        sync.Mutex
        //modified map[usermem.Addr]int
        Perms map[usermem.Addr]usermem.AccessType
}

func NewModAddr() *ModAddr {
    maddr := new(ModAddr)
    //maddr.modified = make(map[usermem.Addr]int)
    maddr.Perms = make(map[usermem.Addr]usermem.AccessType)
    return maddr
}

var TAddrs *TargetAddrs
var TAddr *TargetAddr
var Modaddr *ModAddr

func init() {
    // multiple page
    TAddrs = NewTargetAddrs()

    // single page
    TAddr = NewTargetAddr()
    TAddr.Flag = false
    TAddr.SleepTime = 0
    TAddr.WaitTime = 1000000

    Modaddr = NewModAddr()
}

func Hex2addr(hexStr string) (usermem.Addr, error) {
    // remove 0x suffix if found in the input string
    cleaned := strings.Replace(hexStr, "0x", "", -1)
    cleaned = strings.Replace(cleaned, "\n", "", -1)
    
    // base 16 for hexadecimal
    result, err := strconv.ParseUint(cleaned, 16, 64)
    if err != nil {
        return usermem.Addr(0), err
    }

    //return uint64(result)
    addr := usermem.Addr(uint64(result)).RoundDown()
    return addr, nil
}

func Listen_target_addrs(addrInfo string) {
	log.Debugf("[Cijitter] Get Target Address: %s\n", addrInfo)

    addr_acc := strings.Split(addrInfo, " ")
    if len(addr_acc) != 2 {
        log.Debugf("[Cijitter] Address format error: %s\n", addrInfo)
        return
    }

    // get target address
    addr, err := Hex2addr(addr_acc[0])
    if err != nil {
        log.Debugf("[Cijitter] Address %s transform error: %s\n", addr_acc[0], err)
        return
    }

    // get access number of target address
    access, err := strconv.Atoi(addr_acc[1])
    if err != nil {
        log.Debugf("[Cijitter] Access Number %s transform error: %s\n", addr_acc[1], err)
        access = 1
    }

    log.Debugf("[Cijitter] sysno addr %x, %d\n", addr, access)

	/*
	// lizhi: cpuminer bitcoin -special
    if addr == usermem.Addr(0x514000) {
		log.Debugf("[Cijitter] sysno addr %x, %d, get wrong address\n", addr, access)
		addr = usermem.Addr(0x516000)
	}
	*/

    // lizhi: revision
	if addr == usermem.Addr(0) {
		log.Debugf("[Cijitter] addr is %x, stop delay...\n", addr)
		TAddr.Lock()
		TAddr.Addr = addr
		TAddr.Flag = false
		TAddr.Unlock()
		return
	}

	//sleep time - Microsenconds, 400 is tf
	sleep_time := (0.09 - float64(1/access/270)) * 10000000 - 400
	log.Debugf("[Cijitter] sleep time is %f\n", sleep_time)
	wait_time := 100000/access

	// start to clear the addr's perms
	TAddr.Lock()
	TAddr.Addr = addr
	TAddr.Flag = true
	TAddr.SleepTime = int(sleep_time)
	TAddr.WaitTime = int(wait_time) + 1
	TAddr.Unlock()
}
