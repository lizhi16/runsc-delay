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

var Test string

func init() {
    log.Debugf("[LIZHI] maid initial...")

    // multiple page
    TAddrs = NewTargetAddrs()

    // single page
    TAddr = NewTargetAddr()
    TAddr.Flag = false
    TAddr.SleepTime = 0
    TAddr.WaitTime = 1000000

    Modaddr = NewModAddr()

    Test = "no"
}

func Hex2addr(hexStr string) (usermem.Addr, error) {
    log.Debugf("[LIZHI] Hex2addr: %s", hexStr)

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
