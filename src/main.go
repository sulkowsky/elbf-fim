package main

import (
    "io"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe hello.bpf.c -- -O2 -Wall

func main() {
    objs := probeObjects{}
    if err := loadProbeObjects(&objs, nil); err != nil {
        log.Fatal(err)
    }
    defer objs.Close()


    enterLink, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.EnterOpenat, nil)
    if err != nil {
        log.Fatalf("Failed to attach enter_openat tracepoint: %v", err)
    }
    defer enterLink.Close()

    exitLink, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.ExitOpenat, nil)
    if err != nil {
        log.Fatalf("Failed to attach exit_openat tracepoint: %v", err)
    }
    defer exitLink.Close()

    tracePipe, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
    if err != nil {
        log.Fatal(err)
    }
    defer tracePipe.Close()

    stop := make(chan os.Signal, 1)
    signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-stop
        tracePipe.Close()
    }()

    io.Copy(os.Stdout, tracePipe)
}
