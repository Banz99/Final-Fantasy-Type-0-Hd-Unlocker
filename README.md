# Remove rendering limitations from Final Fantasy Type 0 HD on PC!

## Resolution

This tool allows you inject your own resolution into the game, freeing it from the hardcoded list of resolutions that it normally ships with.
It works by replacing the standard 1080p with your own custom width and height specified in the .ini file (the release is already configured for 2560x1440).

From the fourth release onwards, ultrawide and custom aspect ratios resolutions have also been properly implemented.

**Make sure you have selected 1920x1080 as resolution in the game's own launcher or this won't do anything.**

_Warning_: Setting a resolution unsupported by your primary monitor will close the game immediately on startup.

**BIG WARNING: The game's antialiasing option allows the game to supersample, effectively rendering internally at a resolution that is bigger than the game's final output to your screen to improve image quality. While this was fine @1080p, if you set your resolution to an higher value keep in mind that the high setting will use 2.25 times the number of pixels, and the ultra one will be 4 times! (Example: from 2160p(4k), it would be 3240p and 4320p(8k) respectively). If your monitor supports the resolution you chose but the game is still crashing on startup, try lowering this option.**

## Framerate cap

###  THIS FEATURE HAS BEEN SIGNIFICANTLY IMPROVED SINCE ITS FIRST RELEASE, BUT KEEP IN MIND THAT THERE ARE STILL SOME PROBLEMS.

The framerate patching process uses a runtime assembler (Keystone) and manual memory patches to replicate all the edits that were included in the amazing [PSP cheat code made by LunaMoo](https://forums.ppsspp.org/showthread.php?tid=4799&pid=105556#pid105556) for the original title wherever the game code was a good match between the two versions.
On top of that, a few additions were added wherever some other stuff had been found by me (mostly UI elements).

**The framerate cap can be set to whatever value in the 30-120 fps range you like, however it's highly recommended that you stick to 60/90/120 as those produce the best results being multiples of the original.**

Most of the old psp patch issues [here](http://forums.ppsspp.org/showthread.php?tid=4799&pid=105945#pid105945) have been corrected, but wherever other problems arise, they are much more noticeable the further you go from 30 fps.

_Important_: The game low framerate compensation (frame skipping) doesn't work above 30fps, meaning that if your PC can't reach the FPS target, it will instead slow the speed of the game itself.

The code is largely based on the various SilentPatches released by CookiePLMonster.

Since this is a work in progress, what you see in the release section are what I consider important milestones, but you can get the latest nightly build [here](https://github.com/Banz99/Final-Fantasy-Type-0-Hd-Unlocker/issues/2).

## Field of View

This is just a bonus feature that I discovered when working with ultrawide resolutions. It works by specifying a percentage of the original FOV to apply to the rendered scene, but has also a check to preserve it for cutscenes (that you can disable, should you so desire).

**There is no upper bound limit to this value, however, going past 200 really starts to mess up with the geometry culling functions when moving the camera, so it isn't recommended.**

Note: According to some visual estimates done by the reddit user [Hoshiko-Yoshida](https://www.reddit.com/r/FinalFantasy/comments/w0gb3n/comment/j1mio3v/?utm_source=share&utm_medium=web2x&context=3) which I can't confirm or deny given my ignorance on the matter, the game base FOV seems to be 53/54° hor for the Near camera. Adjust your percentage taking this in mind if you care about having a given value.

## Installation

Download the latest release.zip from github and extract it in your FINAL FANTASY TYPE-0 HD\WIN folder. If you'd like to use the nightly release, download its zip and overwrite FFT0HD Unlocker.asi.

## Credits
* [CookiePLMonster](https://github.com/CookiePLMonster)
* [LunaMoo](https://github.com/LunaMoo)
* [Keystone Engine](https://github.com/keystone-engine/keystone)
* [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)
