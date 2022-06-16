# BlindEye: BattlEye kernel module bypass

![logo](doc\logo.png)

## Overview

BlindEye is a kernel module that prevents the BattlEye kernel module from reporting abnormal data.

## Mechanism

By hooking the `ExAllocatePool` and `ExAllocatePoolWithTag` functions imported by the BattlEye kernel module, the memory allocation requests of the "report" function are dropped and the kernel detections are bypassed.

## Details

[中文](doc/cn.md)

[English](doc/en.md)