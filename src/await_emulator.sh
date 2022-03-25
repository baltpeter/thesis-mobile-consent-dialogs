#!/bin/bash

# Adapted after: https://proandroiddev.com/automated-android-emulator-setup-and-configuration-23accc11a325 and
# https://gist.github.com/mrk-han/db70c7ce2dfdc8ac3e8ae4bec823ba51
animationState=""
failCounter=0
startEmulatorTimeout=60

until [[ "$animationState" =~ "stopped" ]]; do
  animationState=$(adb -e shell getprop init.svc.bootanim 2>&1 &) # Checks state of emulator while in the boot animation

  if [[ "$animationState" =~ "device not found" || "$animationState" =~ "device offline" || "$animationState" =~ "running" ]]; then
    ((failCounter += 1))

    if [[ ${failCounter} -gt ${startEmulatorTimeout} ]]; then
      echo "Timeout of $startEmulatorTimeout seconds reached; failed to start emulator"
      exit 1
    fi
  fi

  sleep 1
done

sleep 10 # Give time for the launcher to appear
