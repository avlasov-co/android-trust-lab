# Glossary

## AVB

Android Verified Boot 2.0, the modern Android verified boot framework.

## vbmeta

Verified boot metadata used by AVB to describe partition verification.

## dm-verity

A Linux kernel feature for verifying block devices through a cryptographic hash tree.

## bootloader lock state

Whether the bootloader is locked, unlocked, or unknown. This affects trust interpretation.

## SELinux enforcing

SELinux policy violations are blocked.

## SELinux permissive

SELinux policy violations are logged but not blocked.

## Magisk

A systemless Android root framework. In this project it is used only as an optional privileged collection environment.

## systemless

A modification approach that avoids directly replacing files on protected system partitions.

## mount namespace

A Linux isolation mechanism that can make mount views differ between processes.

## Zygisk

Magisk feature that injects code into the Zygote process. This project does not implement Zygisk features.

## TEE

Trusted Execution Environment.

## attestation

A mechanism for producing signed statements about device or key state. Hardware-backed attestation is outside the emulator MVP.

## AVD

Android Virtual Device.

## Cuttlefish

Android virtual device platform commonly used for Android development and testing.
