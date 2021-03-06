# Remove rendering limitations from Final Fantasy Type 0 HD on PC!

## Resolution

This tool allows you inject your own resolution into the game, freeing it from the hardcoded list of resolutions that it normally ships with.
It works by replacing the standard 1080p with your own custom width and height specified in the .ini file (the release is already configured for 2560x1440). 

**Make sure you have selected 1920x1080 as resolution in the game's own launcher or this won't do anything.**

_Warning_: Setting a resolution unsupported by your primary monitor will close the game immediately on startup.

**BIG WARNING: The game's antialiasing option allows the game to supersample, effectively rendering internally at a resolution that is bigger than the game's final output to your screen to improve image quality. While this was fine @1080p, if you set your resolution to an higher value keep in mind that the high setting will use 2.25 times the number of pixels, and the ultra one will be 4 times! (Example: from 2160p(4k), it would be 3240p and 4320p(8k) respectively). If your monitor supports the resolution you chose but the game is still crashing on startup, try lowering this option.**

## Framerate cap

###  THIS FEATURE IS HIGHLY EXPERIMENTAL AND AS SUCH EXPECT SOME PROBLEMS.

The framerate patching process uses a runtime assembler (Keystone) and manual memory patches to replicate all the edits that were included in the amazing [PSP cheat code made by LunaMoo](https://forums.ppsspp.org/showthread.php?tid=4799&pid=105556#pid105556) for the original title wherever the game code was a good match between the two versions.
On top of that, a few additions were added wherever some other stuff had been found by me (mostly UI elements).

**The framerate cap can be set to whatever value in the 30-120 fps range you like, however it's highly recommended that you stick to 60/90/120 as those produce the best results being multiples of the original.**

A list of issues that you may encounter is already available [here](http://forums.ppsspp.org/showthread.php?tid=4799&pid=105945#pid105945) (they become more noticeable the further you go from 30 fps).

_Important_: The game low framerate compensation (frame skipping) doesn't work above 30fps, meaning that if your PC can't reach the FPS target, it will instead slow the speed of the game itself.

The code is largely based on the various SilentPatches released by CookiePLMonster.

Since this is a work in progress, what you see in the release section are what I consider important milestones, but you can get the latest nightly build [here](https://github.com/Banz99/Final-Fantasy-Type-0-Hd-Unlocker/issues/2).

## Installation

Download the latest release.zip from github and extract it in your FINAL FANTASY TYPE-0 HD\WIN folder. If you'd like to use the nightly release, download its zip and overwrite FFT0HD Unlocker.asi.

## Credits
* [CookiePLMonster](https://github.com/CookiePLMonster)
* [LunaMoo](https://github.com/LunaMoo)
* [Keystone Engine](https://github.com/keystone-engine/keystone)
* [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)
