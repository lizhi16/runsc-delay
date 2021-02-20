// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kernel

import (
	"bytes"
	"runtime"
	"runtime/trace"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/usermem"

	//lizhi
	"time"
	"fmt"
	//"strings"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/maid"
	//"gvisor.dev/gvisor/pkg/sentry/mm"
)

// A taskRunState is a reified state in the task state machine. See README.md
// for details. The canonical list of all run states, as well as transitions
// between them, is given in run_states.dot.
//
// The set of possible states is enumerable and completely defined by the
// kernel package, so taskRunState would ideally be represented by a
// discriminated union. However, Go does not support sum types.
//
// Hence, as with TaskStop, data-free taskRunStates should be represented as
// typecast nils to avoid unnecessary allocation.
type taskRunState interface {
	// execute executes the code associated with this state over the given task
	// and returns the following state. If execute returns nil, the task
	// goroutine should exit.
	//
	// It is valid to tail-call a following state's execute to avoid the
	// overhead of converting the following state to an interface object and
	// checking for stops, provided that the tail-call cannot recurse.
	execute(*Task) taskRunState
}

// run runs the task goroutine.
//
// threadID a dummy value set to the task's TID in the root PID namespace to
// make it visible in stack dumps. A goroutine for a given task can be identified
// searching for Task.run()'s argument value.

//lizhi
func (t *Task) run(threadID uintptr) {
	//lizhi: initial
	t.tid = fmt.Sprintf("%s-%d", t.tc.Name, threadID)
	t.pgf = true
	t.atFlag = false

	//lizhi: start delay montor
	if t.tc.Name != "sh" && t.tc.Name != "bash" && t.tc.Name != "syscall"{
		go t.monitor_timer()
	}

	// Construct t.blockingTimer here. We do this here because we can't
	// reconstruct t.blockingTimer during restore in Task.afterLoad(), because
	// kernel.timekeeper.SetClocks() hasn't been called yet.
	blockingTimerNotifier, blockingTimerChan := ktime.NewChannelNotifier()
	t.blockingTimer = ktime.NewTimer(t.k.MonotonicClock(), blockingTimerNotifier)
	defer t.blockingTimer.Destroy()
	t.blockingTimerChan = blockingTimerChan

	// Activate our address space.
	t.Activate()

	// The corresponding t.Deactivate occurs in the exit path
	// (runExitMain.execute) so that when
	// Platform.CooperativelySharesAddressSpace() == true, we give up the
	// AddressSpace before the task goroutine finishes executing.

	// If this is a newly-started task, it should check for participation in
	// group stops. If this is a task resuming after restore, it was
	// interrupted by saving. In either case, the task is initially
	// interrupted.
	t.interruptSelf()

	for {
		// Explanation for this ordering:
		//
		// - A freshly-started task that is stopped should not do anything
		// before it enters the stop.
		//
		// - If taskRunState.execute returns nil, the task goroutine should
		// exit without checking for a stop.
		//
		// - Task.Start won't start Task.run if t.runState is nil, so this
		// ordering is safe.
		t.doStop()
		t.runState = t.runState.execute(t)
		if t.runState == nil {
			//lizhi: clean the pgf log for dead thread
			log.Debugf("[LIZHI] thread %s runState is nil: %s-7", t.tid, t.tc.Name)
			t.pgf = false

			groupid := int(t.ThreadGroup().ID())
			if t.tc.Name != "sh" && t.tc.Name != "bash" && t.tc.Name != "syscall"{
				Dthread.Lock()
				if _, ok := Dthread.Threads[groupid]; ok {
					delete(Dthread.Threads[groupid], t.tid)
					//new thread strat to implement delay
					if t.tid == Dthread.Worker {
						for thread, _ := range Dthread.Threads[groupid]{
							log.Debugf("[LIZHI] thread %s implement delay", thread)
							Dthread.Threads[groupid][thread] = 1
							Dthread.Worker = thread
							break
						}
					}
				}
				Dthread.Unlock()
			}
			//end

			t.accountTaskGoroutineEnter(TaskGoroutineNonexistent)
			t.goroutineStopped.Done()
			t.tg.liveGoroutines.Done()
			t.tg.pidns.owner.liveGoroutines.Done()
			t.tg.pidns.owner.runningGoroutines.Done()
			t.p.Release()

			// Keep argument alive because stack trace for dead variables may not be correct.
			runtime.KeepAlive(threadID)
			return
		}
	}
}

// doStop is called by Task.run to block until the task is not stopped.
func (t *Task) doStop() {
	if atomic.LoadInt32(&t.stopCount) == 0 {
		return
	}
	t.Deactivate()
	// NOTE(b/30316266): t.Activate() must be called without any locks held, so
	// this defer must precede the defer for unlocking the signal mutex.
	defer t.Activate()
	t.accountTaskGoroutineEnter(TaskGoroutineStopped)
	defer t.accountTaskGoroutineLeave(TaskGoroutineStopped)
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.tg.pidns.owner.runningGoroutines.Add(-1)
	defer t.tg.pidns.owner.runningGoroutines.Add(1)
	t.goroutineStopped.Add(-1)
	defer t.goroutineStopped.Add(1)
	for t.stopCount > 0 {
		t.endStopCond.Wait()
	}
}

func (*runApp) handleCPUIDInstruction(t *Task) error {
	if len(arch.CPUIDInstruction) == 0 {
		// CPUID emulation isn't supported, but this code can be
		// executed, because the ptrace platform returns
		// ErrContextSignalCPUID on page faults too. Look at
		// pkg/sentry/platform/ptrace/ptrace.go:context.Switch for more
		// details.
		return platform.ErrContextSignal
	}
	// Is this a CPUID instruction?
	region := trace.StartRegion(t.traceContext, cpuidRegion)
	expected := arch.CPUIDInstruction[:]
	found := make([]byte, len(expected))
	_, err := t.CopyIn(usermem.Addr(t.Arch().IP()), &found)
	if err == nil && bytes.Equal(expected, found) {
		// Skip the cpuid instruction.
		t.Arch().CPUIDEmulate(t)
		t.Arch().SetIP(t.Arch().IP() + uintptr(len(expected)))
		region.End()

		return nil
	}
	region.End() // Not an actual CPUID, but required copy-in.
	return platform.ErrContextSignal
}

// The runApp state checks for interrupts before executing untrusted
// application code.
//
// +stateify savable
type runApp struct{}

func (app *runApp) execute(t *Task) taskRunState {
	if t.interrupted() {
		// Checkpointing instructs tasks to stop by sending an interrupt, so we
		// must check for stops before entering runInterrupt (instead of
		// tail-calling it).
		return (*runInterrupt)(nil)
	}

	// We're about to switch to the application again. If there's still a
	// unhandled SyscallRestartErrno that wasn't translated to an EINTR,
	// restart the syscall that was interrupted. If there's a saved signal
	// mask, restore it. (Note that restoring the saved signal mask may unblock
	// a pending signal, causing another interruption, but that signal should
	// not interact with the interrupted syscall.)
	if t.haveSyscallReturn {
		if sre, ok := SyscallRestartErrnoFromReturn(t.Arch().Return()); ok {
			if sre == ERESTART_RESTARTBLOCK {
				t.Debugf("Restarting syscall %d with restart block after errno %d: not interrupted by handled signal", t.Arch().SyscallNo(), sre)
				t.Arch().RestartSyscallWithRestartBlock()
			} else {
				t.Debugf("Restarting syscall %d after errno %d: not interrupted by handled signal", t.Arch().SyscallNo(), sre)
				t.Arch().RestartSyscall()
			}
		}
		t.haveSyscallReturn = false
	}
	if t.haveSavedSignalMask {
		t.SetSignalMask(t.savedSignalMask)
		t.haveSavedSignalMask = false
		if t.interrupted() {
			return (*runInterrupt)(nil)
		}
	}

	// Apply restartable sequences.
	if t.rseqPreempted {
		t.rseqPreempted = false
		if t.rseqAddr != 0 || t.oldRSeqCPUAddr != 0 {
			// Linux writes the CPU on every preemption. We only do
			// so if it changed. Thus we may delay delivery of
			// SIGSEGV if rseqAddr/oldRSeqCPUAddr is invalid.
			cpu := int32(hostcpu.GetCPU())
			if t.rseqCPU != cpu {
				t.rseqCPU = cpu
				if err := t.rseqCopyOutCPU(); err != nil {
					t.Debugf("Failed to copy CPU to %#x for rseq: %v", t.rseqAddr, err)
					t.forceSignal(linux.SIGSEGV, false)
					t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
					// Re-enter the task run loop for signal delivery.
					return (*runApp)(nil)
				}
				if err := t.oldRSeqCopyOutCPU(); err != nil {
					t.Debugf("Failed to copy CPU to %#x for old rseq: %v", t.oldRSeqCPUAddr, err)
					t.forceSignal(linux.SIGSEGV, false)
					t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
					// Re-enter the task run loop for signal delivery.
					return (*runApp)(nil)
				}
			}
		}
		t.rseqInterrupt()
	}

	// Check if we need to enable single-stepping. Tracers expect that the
	// kernel preserves the value of the single-step flag set by PTRACE_SETREGS
	// whether or not PTRACE_SINGLESTEP/PTRACE_SYSEMU_SINGLESTEP is used (this
	// includes our ptrace platform, by the way), so we should only clear the
	// single-step flag if we're responsible for setting it. (clearSinglestep
	// is therefore analogous to Linux's TIF_FORCED_TF.)
	//
	// Strictly speaking, we should also not clear the single-step flag if we
	// single-step through an instruction that sets the single-step flag
	// (arch/x86/kernel/step.c:is_setting_trap_flag()). But nobody sets their
	// own TF. (Famous last words, I know.)
	clearSinglestep := false
	if t.hasTracer() {
		t.tg.pidns.owner.mu.RLock()
		if t.ptraceSinglestep {
			clearSinglestep = !t.Arch().SingleStep()
			t.Arch().SetSingleStep()
		}
		t.tg.pidns.owner.mu.RUnlock()
	}

	region := trace.StartRegion(t.traceContext, runRegion)
	t.accountTaskGoroutineEnter(TaskGoroutineRunningApp)
	info, at, err := t.p.Switch(t.MemoryManager().AddressSpace(), t.Arch(), t.rseqCPU)
	
	//lizhi
	t.At = at
	t.atFlag = true

	t.accountTaskGoroutineLeave(TaskGoroutineRunningApp)
	region.End()

	if clearSinglestep {
		t.Arch().ClearSingleStep()
	}

	switch err {
	case nil:
		/* old version
		lizhi: listen the target addr and clear its perms to trigger seg fault
		if t.tc.Name != "sh" && t.tc.Name != "bash" { //&& t.tc.Name != "syscall"{
			Listen_target_addrs(t)
		}
		*/

		// Handle application system call.
		return t.doSyscall()

	case platform.ErrContextInterrupt:
		// Interrupted by platform.Context.Interrupt(). Re-enter the run
		// loop to figure out why.
		return (*runApp)(nil)

	case platform.ErrContextSignalCPUID:
		if err := app.handleCPUIDInstruction(t); err == nil {
			// Resume execution.
			return (*runApp)(nil)
		}

		// The instruction at the given RIP was not a CPUID, and we
		// fallthrough to the default signal deliver behavior below.
		fallthrough

	case platform.ErrContextSignal:
		// Looks like a signal has been delivered to us. If it's a synchronous
		// signal (SEGV, SIGBUS, etc.), it should be sent to the application
		// thread that received it.
		sig := linux.Signal(info.Signo)

		// Was it a fault that we should handle internally? If so, this wasn't
		// an application-generated signal and we should continue execution
		// normally.
		if at.Any() {
			region := trace.StartRegion(t.traceContext, faultRegion)
			addr := usermem.Addr(info.Addr())

			//lizhi: refund the perms to the addrs modified by us
			flag := false
			if t.tc.Name != "sh" && t.tc.Name != "bash" && t.tc.Name != "syscall" {
				Modify.Lock()
				//lizhi: flag depicts if the addr is handled by us
				flag = t.handle_seg_faults(addr)
				if flag == false {
					Modify.Unlock()
				}
			}
			
			err := t.MemoryManager().HandleUserFault(t, addr, at, usermem.Addr(t.Arch().Stack()))
			//lizhi; ensure the the refund processing is locked
			if flag == true {
				Modify.Unlock()
			}
			
			region.End()
			if err == nil {
				// The fault was handled appropriately.
				// We can resume running the application.
				return (*runApp)(nil)
			}

			// Is this a vsyscall that we need emulate?
			//
			// Note that we don't track vsyscalls as part of a
			// specific trace region. This is because regions don't
			// stack, and the actual system call will count as a
			// region. We should be able to easily identify
			// vsyscalls by having a <fault><syscall> pair.
			if at.Execute {
				if sysno, ok := t.tc.st.LookupEmulate(addr); ok {
					return t.doVsyscall(addr, sysno)
				}
			}

			// Faults are common, log only at debug level.
			//lizhi add %s
			t.Debugf("%s Unhandled user fault: addr=%x ip=%x access=%v err=%v", t.tid, addr, t.Arch().IP(), at, err)
			t.DebugDumpState()

			// Continue to signal handling.
			//
			// Convert a BusError error to a SIGBUS from a SIGSEGV. All
			// other info bits stay the same (address, etc.).
			if _, ok := err.(*memmap.BusError); ok {
				sig = linux.SIGBUS
				info.Signo = int32(linux.SIGBUS)
			}
		}

		switch sig {
		case linux.SIGILL, linux.SIGSEGV, linux.SIGBUS, linux.SIGFPE, linux.SIGTRAP:
			// Synchronous signal. Send it to ourselves. Assume the signal is
			// legitimate and force it (work around the signal being ignored or
			// blocked) like Linux does. Conveniently, this is even the correct
			// behavior for SIGTRAP from single-stepping.
			t.forceSignal(linux.Signal(sig), false /* unconditional */)
			t.SendSignal(info)

		case platform.SignalInterrupt:
			// Assume that a call to platform.Context.Interrupt() misfired.

		case linux.SIGPROF:
			// It's a profiling interrupt: there's not much
			// we can do. We've already paid a decent cost
			// by intercepting the signal, at this point we
			// simply ignore it.

		default:
			// Asynchronous signal. Let the system deal with it.
			t.k.sendExternalSignal(info, "application")
		}

		return (*runApp)(nil)

	case platform.ErrContextCPUPreempted:
		// Ensure that rseq critical sections are interrupted and per-thread
		// CPU values are updated before the next platform.Context.Switch().
		t.rseqPreempted = true
		return (*runApp)(nil)

	default:
		// What happened? Can't continue.
		t.Warningf("Unexpected SwitchToApp error: %v", err)
		t.PrepareExit(ExitStatus{Code: ExtractErrno(err, -1)})
		return (*runExit)(nil)
	}
}

// waitGoroutineStoppedOrExited blocks until t's task goroutine stops or exits.
func (t *Task) waitGoroutineStoppedOrExited() {
	t.goroutineStopped.Wait()
}

// WaitExited blocks until all task goroutines in tg have exited.
//
// WaitExited does not correspond to anything in Linux; it's provided so that
// external callers of Kernel.CreateProcess can wait for the created thread
// group to terminate.
func (tg *ThreadGroup) WaitExited() {
	tg.liveGoroutines.Wait()
}

// Yield yields the processor for the calling task.
func (t *Task) Yield() {
	atomic.AddUint64(&t.yieldCount, 1)
	runtime.Gosched()
}

//lizhi
/*
func Listen_target_addrs(t *Task) {
	sysno := t.Arch().SyscallNo()
	args := t.Arch().SyscallArgs()
	if int(sysno) == 308 {
			log.Debugf("[LIZHI] sysno in run: %d\n", sysno)
			//log.Debugf("[LIZHI] sysargvs in run: %x, %x\n", args[0].Value, args[1].Value)

			// receive the addr needs to clear perms from syscall 308
			para1 := args[0].Value << 32
			para2 := args[1].Value

			addr_str := para1 | para2
			addr := usermem.Addr(addr_str).RoundDown()
			log.Debugf("[LIZHI] sysno addr %x\n", addr)

			// start to clear the addr's perms
			maid.TAddr.Lock()
			maid.TAddr.Addr = addr
			maid.TAddr.Flag = true
			maid.TAddr.Unlock()
	}
}
*/

//lizhi
/* revision: 2nd old version */
/*func Listen_target_addrs(t *Task) {
	sysno := t.Arch().SyscallNo()
	args := t.Arch().SyscallArgs()
	if int(sysno) == 308 {
			log.Debugf("[LIZHI] sysno in run: %d\n", sysno)
			//log.Debugf("[LIZHI] sysargvs in run: %x, %x\n", args[0].Value, args[1].Value)

			// receive the addr needs to clear perms from syscall 308
			upper := args[0].Value / 1000
			access := args[0].Value % 1000

			para1 := upper << 32
			para2 := args[1].Value

			addr_str := para1 | para2
			addr := usermem.Addr(addr_str).RoundDown()

			
			// lizhi: cpuminer bitcoin -special
			//if addr == usermem.Addr(0x514000) {
			//	log.Debugf("[LIZHI] sysno addr %x, %d, get wrong address\n", addr, access)
			//	addr = usermem.Addr(0x516000)
			//}

			log.Debugf("[LIZHI] sysno addr %x, %d\n", addr, access)

			// lizhi: revision
			if addr == usermem.Addr(0) {
				log.Debugf("[LIZHI] addr is %x, stop delay...\n", addr)
				maid.TAddr.Lock()
				maid.TAddr.Addr = addr
				maid.TAddr.Flag = false
				maid.TAddr.Unlock()
				return
			}

			// judge if this page needs to be delayed
			if access <= 80 {
				log.Debugf("[LIZHI] sysno addr %x is not target\n", addr)
				return
			}

			//sleep time - Microsenconds, 400 is tf
			sleep_time := (0.09 - float64(1/access/270)) * 10000000 - 400
			log.Debugf("[LIZHI] sleep time is %f\n", sleep_time)
			wait_time := 100000/access

			// start to clear the addr's perms
			maid.TAddr.Lock()
			maid.TAddr.Addr = addr
			maid.TAddr.Flag = true
			maid.TAddr.SleepTime = int(sleep_time)
			maid.TAddr.WaitTime = int(wait_time) + 1
			maid.TAddr.Unlock()
	}
}*/

func (t *Task) handle_seg_faults(addr usermem.Addr) bool {
	new_addr := addr.RoundDown()
	log.Debugf("[LIZHI] %s Handle seg faults: %x, %x\n", t.tid, addr, new_addr)

	// refund the perms to the addr modified by us.
	org_perms, ok := Modify.perms[new_addr]
	if !ok {
		log.Debugf("[LIZHI] %s Addr %x not in modified list\n", t.tid, new_addr)
		return false
	}

	// two threads maybe get the seg faults at the same time
	/*if Modify.modified[new_addr] == 0 {
	log.Debugf("[LIZHI] %s Addr %x have been refunded\n", t.tid, new_addr)
			return true
	}*/

	log.Debugf("[LIZHI] Addr %x in modified list, mprotect perms %s\n", new_addr, org_perms.String())
	if err := t.MemoryManager().MProtect(new_addr, usermem.PageSize, org_perms, false); err != nil {
		log.Debugf("[LIZHI] Addr %x refund failed %v", new_addr, err)
		//need?
		Modify.modified[new_addr] = 0
		Modify.master = ""

		return true
	}
	Modify.modified[new_addr] = 0
 	Modify.master = ""

 	log.Debugf("[LIZHI] Addr %x refund success", new_addr)

 	//delay revision test
	/*
	maid.TAddr.Lock()
	sleep_time := maid.TAddr.SleepTime
	maid.TAddr.Unlock()

	time.Sleep(time.Duration(sleep_time) * time.Microsecond)
	*/

	return true
}

func (t *Task) start_delay(addr usermem.Addr) {
	log.Debugf("[LIZHI] %s start to clear %x\n", t.tid, addr)

	//judge addr is legal and get real perms
	if t.atFlag == false {
		log.Debugf("[LIZHI] %s t.At is nil, can't delay\n", t.tid)
		return
	}

	if t == nil || t.MemoryManager() == nil {
		return
	}

	if addr == usermem.Addr(0) {
		return
	}

	org_perms, err := t.MemoryManager().GetAddrPerms(t, addr, t.At)
	if err != nil {
		log.Debugf("[LIZHI] can't get the original perms: %x, %v\n", addr, err)
		return
	}

	//mprotect to clear perms, and make sure only one thread is handling this addr
	Modify.Lock()
	defer Modify.Unlock()

	// get lock, but it doesn't need to clear
	maid.TAddr.Lock()
	clear_stats := maid.TAddr.Flag
	target_addr := maid.TAddr.Addr
	maid.TAddr.Unlock()

	if !clear_stats || target_addr != addr {
		log.Debugf("[LIZHI] new delay round start, stop clear %x...", addr)
		return
	}

	// start clear
	stats, ok := Modify.modified[addr]
	if ok && stats == 1 {
		log.Debugf("[LIZHI] %s detect %x is being handled by %s", t.tid, addr, Modify.master)
		return
    }

	/*
	stats, ok := Modify.modified[addr]
	if !ok {
		Modify.modified[addr] = 1
		Modify.master = t.tid
	// nobody handle this addr
	} else if stats == 0 {
		Modify.modified[addr] = 1
		Modify.master = t.tid
	// this addr are being handled (doesn't refund perms)
	} else if stats == 1 {
		log.Debugf("[LIZHI] %s detect %x is being handled by %s", t.tid, addr, Modify.master)
		return
	}
	*/

	// save the perms for each time delay:
	// multiple threads: two threads clear the perms
	// in second, the org_perms is ---
	perms, ok := Modify.perms[addr]
	if !ok {
		Modify.perms[addr] = org_perms
	} else {
		Modify.perms[addr] = perms.Union(org_perms)
	}

	//Modify.Unlock()

	err = t.MemoryManager().MProtect(addr, usermem.PageSize, usermem.NoAccess, false)
	if err != nil {
		log.Debugf("[LIZHI] clear %x perms failed: %v\n", addr, err)
		return
	}

	log.Debugf("[LIZHI] %s clear %x success.\n", t.tid, addr)
	// log the success
	Modify.modified[addr] = 1
        Modify.master = t.tid

	// delay time: not back lock, the refund needs to wait
	maid.TAddr.Lock()
        sleep_time := maid.TAddr.SleepTime
        maid.TAddr.Unlock()

        time.Sleep(time.Duration(sleep_time) * time.Microsecond)
}

func (t *Task) monitor_timer() {
	log.Debugf("[LIZHI] start delayer for thread %s", t.tid)
	//tick := time.NewTicker(1 * time.Second)
	//tick := time.NewTicker(10 * time.Millisecond)

	maid.TAddr.Lock()
    wait_time := maid.TAddr.WaitTime
    maid.TAddr.Unlock()
	tick := time.NewTicker(time.Duration(wait_time) * time.Microsecond)
	log.Debugf("[LIZHI] started tick is %d\n", wait_time)
	//tick := time.NewTicker(10000 * time.Microsecond)

	defer tick.Stop()

	index := 0
	for {
		<-tick.C

		//judge if need to start delay mechanism in this thread
		Dthread.RLock()
		if t.tid != Dthread.Worker {
			//log.Debugf("[LIZHI] thread %s is sleeping...", t.tid)
			Dthread.RUnlock()
			continue
		}
		Dthread.RUnlock()

		index ++

		//judge thread statue
		if t.pgf == false {
			log.Debugf("[LIZHI] thread %s: monitor exit", t.tid)
			return	//or use "continue"
		}

		// handling records to get page faults
		var pages []usermem.Addr

		/* delay multiple pages
		maid.TAddrs.Lock()
		for page, _ := range maid.TAddrs.Addrs {
			pages = append(pages, page)
		}
		maid.TAddrs.Unlock()
		*/

		//delay single page
		maid.TAddr.Lock()
		addr := maid.TAddr.Addr
		if maid.TAddr.Flag == true {
			log.Debugf("[LIZHI] thread %s get the delay pages %x", t.tid, addr)
			pages = append(pages, addr)
		} else {
			log.Debugf("[LIZHI]---- target page is null ----\n")
			maid.TAddr.Unlock()
			continue
		}
		//maid.TAddr.Unlock()

	    wait_time := maid.TAddr.WaitTime
	    maid.TAddr.Unlock()
		tick = time.NewTicker(time.Duration(wait_time) * time.Microsecond)
		log.Debugf("[LIZHI] ended tick is %d\n", wait_time)

		// start to delay
		if len(pages) == 0 {
			log.Debugf("[LIZHI] thread %s no pages to delay", t.tid)
			index --
			continue
		}

		log.Debugf("[LIZHI] thread %s start %d round delay ", t.tid, index)
		for target := range pages {
			t.start_delay(pages[target])
		}
	}
}
