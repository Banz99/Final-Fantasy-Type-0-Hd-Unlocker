#include "Utils/MemoryMgr.h"
#include "Utils/Patterns.h"

#include <Shlwapi.h>

#include <string_view>
#include <math.h>
#include "Utils/Trampoline.h"
#include "include/keystone/keystone.h"


#pragma comment(lib, "Shlwapi.lib")

wchar_t wcModulePath[MAX_PATH];
static HMODULE hDLLModule;

/*Keystone Imports*/
typedef ks_err(__stdcall* ks_open_dll)(ks_arch arch, int mode, ks_engine** ks);
typedef int(__stdcall* ks_asm_dll)(ks_engine* ks, const char* string, uint64_t address, unsigned char** encoding, size_t* encoding_size, size_t* stat_count);
typedef void(__stdcall* ks_free_dll)(unsigned char* p);

ks_engine* ks;
ks_open_dll ks_open_fnc;
ks_asm_dll ks_asm_fnc;
ks_free_dll ks_free_fnc;
HMODULE hDLLKeystone;

float DecreaseFloatPrecision(float input, uint8_t nbits) {
	if (nbits == 0)
		return input;
	uint32_t mask = 0xFFFFFFFF - ((uint32_t)pow(2, nbits) - 1);
	uint32_t temp = *(uint32_t*)&input; //Necessary evil bithack that decreases the float's precision. (Only 60 and 120 fps will be 100% correct, every other value will be lower, resulting in a slight speedup or slowdown depending on context)
	temp = temp & mask;
	return *(float*)&temp;
}


int LoadXMMRegisterJump(const char* previousinstructions, const char* xmmbase, const char* immediateregister, float value, const char* followinginstructions, unsigned char** encode, size_t* size)
{
	size_t count;
	char producedassembly[500];
	sprintf_s(producedassembly, "%s; mov %s, 0x%x; movd %s, %s; %s; jmp 0x1000000", previousinstructions, immediateregister, *(uint32_t*)&value, xmmbase, immediateregister, followinginstructions);
	return ks_asm_fnc(ks, producedassembly, 0, encode, size, &count);
}

int ModifyXMMRegisterJump(const char* previousinstructions, const char* xmminstruction, const char* xmmbase, const char* xmmtemp, const char* immediateregister, float value, const char* followinginstructions, unsigned char** encode, size_t* size)
{
	size_t count;
	char producedassembly[500];
	sprintf_s(producedassembly, "%s; mov %s, 0x%x; movd %s, %s; %s %s, %s; %s; jmp 0x1000000", previousinstructions, immediateregister, *(uint32_t*)&value, xmmtemp, immediateregister, xmminstruction, xmmbase, xmmtemp, followinginstructions);
	return ks_asm_fnc(ks, producedassembly, 0, encode, size, &count);
}

void OnInitializeHook()
{

	GetModuleFileNameW(hDLLModule, wcModulePath, _countof(wcModulePath) - 3); // Minus max required space for extension
	PathRenameExtensionW(wcModulePath, L".ini");

	using namespace Memory::VP;
	using namespace hook;

	const int ResX = GetPrivateProfileIntW(L"OverrideRes", L"ResX", 0, wcModulePath);
	const int ResY = GetPrivateProfileIntW(L"OverrideRes", L"ResY", 0, wcModulePath);

	if (ResX > 0 && ResY > 0)
	{
		auto windowres = pattern("C4 40 5F C3 C7 07 80 07 00 00 C7 03 38 04 00 00").count(1);
		if (windowres.size() == 1)
		{
			Patch<int32_t>(windowres.get_first<void>(0x6), ResX);
			Patch<int32_t>(windowres.get_first<void>(0xC), ResY);
		}

		auto renderres = pattern("75 21 41 0B C4 B9 80 07 00 00 BA 38 04 00 00").count(1);

		if (renderres.size() == 1)
		{
			Patch<int32_t>(renderres.get_first<void>(0x6), ResX);
			Patch<int32_t>(renderres.get_first<void>(0xB), ResY);
		}
	}

	const int framerateint = GetPrivateProfileIntW(L"OverrideFramerate", L"FpsCap", 0, wcModulePath);

	if (framerateint > 30) {

		hDLLKeystone = LoadLibrary(L"keystone.dll");

		ks_err err;
		size_t count;
		unsigned char* encode;
		size_t size = 0;


		ks_open_fnc = (ks_open_dll)GetProcAddress(hDLLKeystone, "ks_open");
		ks_asm_fnc = (ks_asm_dll)GetProcAddress(hDLLKeystone, "ks_asm");
		ks_free_fnc = (ks_free_dll)GetProcAddress(hDLLKeystone, "ks_free");

		if (ks_open_fnc && ks_asm_fnc && ks_free_fnc) {

			float framerate = framerateint;

			if (framerate > 120.0f) {
				MessageBox(
					NULL,
					(LPCWSTR)L"Due to technical limitations, the framerate of the game cannot exceed 120fps.\nTo make this message disappear on startup, lower the value in FFT0HD Resolution Unlocker.ini.\nThe game will now start with a 120fps cap.",
					(LPCWSTR)L"Framerate Warning",
					MB_ICONWARNING | MB_OK
				);
				framerate = 120.0f;
			}

			Trampoline* trampoline = Trampoline::MakeTrampoline(GetModuleHandle(nullptr));
			std::byte* space;
			err = ks_open_fnc(KS_ARCH_X86, KS_MODE_64, &ks);

			/*[ref] points to the absolute address in the PSP elf on which similar patches were applied*/

			//Actual value used for the frame limiter (also likely to [ref: 0x0008614C] since there are no other 0.0333333 floats referenced in the code)
			auto frameratelimit = pattern("88 88 08 3D 89 88 08 3D 35 FA 0E 3D 29 5C 0F 3D").count(1);
			Patch<float>(frameratelimit.get_first<void>(0x4), 1.0f / framerate);
			DWORD dwProtect;
			VirtualProtect((void*)frameratelimit.get_first<void>(0x4), sizeof(float), PAGE_EXECUTE_READWRITE, &dwProtect); //This variable needs to be writable by the movie function below

			//Framerate here is used as an integer
			//[ref: 0x0004F084]
			auto frint1 = pattern("88 42 30 B0 01 C3 04 1E 88 42 30 32 C0 C3 CC").count(1);
			Patch<byte>(frint1.get_first<void>(0x7), (byte)framerate);
			//[ref: 0x00179AEC]
			auto frint2 = pattern("05 7F 4A 3E 00 83 F8 1E 7C 23 C7 05 70 4A 3E").count(1);
			Patch<byte>(frint2.get_first<void>(0x7), (byte)framerate);
			/*//[ref: 0x00208D84] Kinda dangerous, crashes the game if actually applied
			auto frint3 = pattern("51 01 00 00 81 BB 70 6E 00 00 84 03 00 00 0F 8E").count(1);
			Patch<uint32_t>(frint1.get_first<void>(0xA), (uint32_t)framerate*30);
			*/
			//Party stats pop up time (when not in battle or near a relic terminal)
			auto frint4 = pattern("FF FF 32 C0 EB 70 C7 05 AF BC 37 00 96 00 00 00").count(1);
			Patch<uint32_t>(frint4.get_first<void>(0xC), (framerate / 30.0f) * 150.0f);
			frint4 = pattern("0F 84 7D 00 00 00 C7 05 7A BC 37 00 96 00 00 00").count(1);
			Patch<uint32_t>(frint4.get_first<void>(0xC), (framerate / 30.0f) * 150.0f);
			frint4 = pattern("ED BB 37 00 EB 91 C7 05 E1 BB 37 00 96 00 00 00").count(1);
			Patch<uint32_t>(frint4.get_first<void>(0xC), (framerate / 30.0f) * 150.0f);
			frint4 = pattern("08 01 00 00 75 84 C7 05 0C BD 37 00 96 00 00 00").count(1);
			Patch<uint32_t>(frint4.get_first<void>(0xC), (framerate / 30.0f) * 150.0f);
			//"Reraise" and other status effects on top of the characters name
			auto frint5 = pattern("C0 75 43 41 FF 40 08 41 83 78 08 14 0F 8C B1 00").count(1);
			Patch<byte>(frint5.get_first<void>(0xB), (framerate / 30.0f) * 20.0f);
			frint5 = pattern("D1 73 43 41 FF 40 08 41 83 78 08 14 7C 66 83 F8").count(1);;
			Patch<byte>(frint5.get_first<void>(0xB), (framerate / 30.0f) * 20.0f);
			//Flashing examine button
			auto frint6 = pattern("DB 78 4E 8B 4D CB FF C9 75 47 2B FA 83 FB 14 7C").count(1);
			Patch<byte>(frint6.get_first<void>(0xE), (framerate / 30.0f) * 20.0f);
			frint6 = pattern("00 69 C9 00 00 00 0D 2B C1 EB 24 83 FB 0A 7D 11").count(1);
			Patch<byte>(frint6.get_first<void>(0x6), 255.0f / ((framerate / 30.0f) * 19.0f)); //0x0D000000 is a uint32_t but the only relevant part are the highest 8 bits (0D) since it's used to calculate the alpha channel.
			Patch<byte>(frint6.get_first<void>(0xD), (framerate / 30.0f) * 10.0f);
			frint6 = pattern("8B CB B8 00 00 00 FF 69 C9 00 00 00 0D 2B C1 EB").count(1);
			Patch<byte>(frint6.get_first<void>(0xC), 255.0f / ((framerate / 30.0f) * 19.0f));
			frint6 = pattern("0E 8B C3 69 C0 00 00 00 0D 81 C7 00 00 00 FB 03").count(1);
			Patch<byte>(frint6.get_first<void>(0x8), 255.0f / ((framerate / 30.0f) * 19.0f));

			//[ref: 0x000A9AF4]
			auto charactersanimationspeed = pattern("80 A3 B6 09 00 00 F7 C7 83 D8 05 00 00 00 00 80 3F");
			Patch<float>(charactersanimationspeed.get_first<void>(0xD), framerate != 60.0f ? 30.0f / framerate : 29.9f / framerate); //The lip sync function that the game uses for real time cutscenes REALLY doesn't like 0.5f as a value here.

			auto movielimit = pattern("02 32 C9 48 8B 05 7E F9 60 00 88 88 D0 00 00 00").count(1);
			size_t size;
			if (!ks_asm_fnc(ks,"mov[rax + 0D0h], cl; cmp cl, 0; je A; mov dword ptr [rip + 0x410e3a], 0x3D088889; jmp B; A: mov dword ptr [rip + 0x410e3a], 0x3C888889; B: jmp 0x10000000",0,&encode,&size,&count))
			{
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + 13, frameratelimit.get_first<void>(0x4 - 4));
				WriteOffsetValue(space + 25, frameratelimit.get_first<void>(0x4 - 4));
				Patch<float>(space + 29, 1.0f / framerate);
				WriteOffsetValue(space + size - 4, movielimit.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(movielimit.get_first<void>(0xA), space, PATCH_JUMP);
			}

			//Characters walking speeds (also in cutscenes) [ref: 0x00083CF8]
			auto match = pattern("24 20 0F 2F C1 F3 0F 10 71 38 76 5E E8 EF F9 FE").count(1);
			if (!ModifyXMMRegisterJump("movss xmm6, dword ptr[rcx + 38h]", "mulss", "xmm6", "xmm7", "edx", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xA)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}

			//Controlled character turning speed (a bit broken above 90 fps) [ref: 0x00006734 to 0x00006744]
			match = pattern("F3 0F 59 49 40 F3 0F 59 CA F3 0F 59 51 34 F3 0F 59 0D 1F C4 3A 00").count(1);
			if (!ModifyXMMRegisterJump("movss xmm1, dword ptr [rcx+40h]; movss xmm2, dword ptr [rcx+34h]", "mulss", "xmm1", "xmm7", "edx", 15.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x16)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}

			//First cutscene slow-motion walk speed [ref: 0x00006998]
			match = pattern("20 5B C3 F3 0F 10 41 04 F3 0F 58 05 69 BE 3A 00").count(1);
			if (!ModifyXMMRegisterJump("", "addss", "xmm0", "xmm7", "edx", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//Camera distance in cutscenes [ref: 0x00155CB0]
			match = pattern("00 44 0F 29 44 24 70 F3 44 0F 10 05 DC BF 29 00").count(1);
			if (!LoadXMMRegisterJump("", "xmm8", "edx", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}

			//Cutscene timings [ref: 0x00127D90]
			match = pattern("2F C8 76 04 C6 41 2C 01 F3 0F 5C 0D 93 34 22 00").count(1);
			if (!ModifyXMMRegisterJump("", "subss", "xmm1", "xmm7", "edx", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//Part of the HUD [ref: 0x002491E4]
			match = pattern("0F 5B C0 F3 0F 5E C8 F3 0F 58 CA 41 0F 2F CF").count(1);
			if (!ModifyXMMRegisterJump("divss xmm1, xmm0", "mulss", "xmm1", "xmm7", "eax", 30.0f / framerate, "addss xmm1, xmm2", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xB)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x3), space, PATCH_JUMP);
			}

			//[ref: 0x001F9924 and 0x001F9934]
			match = pattern("05 57 A6 24 00 F3 41 0F 59 C8 D1 E8 41 84 C7 74").count(1);
			if (!ModifyXMMRegisterJump("mulss xmm1, xmm8", "mulss", "xmm1", "xmm6", "edx", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xA)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}

			//[ref: 0x002A13A8]
			match = pattern("05 93 57 2C 00 F3 41 0F 10 84 06 B8 00 00 00 0F").count(1);
			if (!ModifyXMMRegisterJump("movss xmm0, dword ptr[r14 + rax + 0B8h]", "mulss", "xmm0", "xmm7", "edx", framerate / 30.0f, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xF)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}

			//Gameplay fixes #1 (i.e guards falling into the ground below when dropping from the ship at the beginning of the game) Note: the check for dword_140658F70 determines if it's in a cutscene (and always use 1.0 in that case) and the < 5.0 check is for avoiding softlocks when enemies are supposed to spawn later [ref: 0x0013D75C]
			match = pattern("8B 43 08 F3 0F 10 04 88 F3 0F 58 05 3C DE 20 00").count(1);

			/* Failed attempt at fixing the imprecise float accumulation described below, rounding introduced more problems than those it fixed
			auto floataccumulator = trampoline->RawSpace(sizeof(float));
			size_t size;
			if (!ks_asm_fnc(ks, "movss xmm11, dword ptr [rip + 7654321h]; mov r10, rax; call 0xfffffffffffda9b8; test rax, rax; jz B; cmp dword ptr [rax + 0x48], 0; mov rax, r10; jnz A; B: mov edx, 0x40A00000; movd xmm7, edx; comiss xmm0, xmm7; jb A; mov edx, 0x3eaaaaab; movd xmm7, edx; addss xmm11, xmm7; addss xmm0, xmm7; jmp C; A: mov edx, 0x3F800000; movd xmm7, edx; addss xmm11, xmm7; addss xmm0, xmm7; C: movss dword ptr [rip + 7654321h], xmm11; mov edx, 0x3F800000; movd xmm7, edx; comiss xmm11, xmm7; jb D; mov dword ptr [rip + 7654321h], 0; cvtss2si edx, xmm0; cvtsi2ss xmm0, edx; D: nop; jmp 0x1000000", 0, &encode, &size, &count)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + 5, floataccumulator);
				WriteOffsetValue(space + 88, floataccumulator);
				WriteOffsetValue(space + 109, floataccumulator-4);
				WriteOffsetValue(space + 13, match.get_first<void>(0x8 + 0xfffda9b8)); //Third byte of a mov instruction is the address, gets computed so that it points to dword_140658F70
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}
			*/

			if (!ModifyXMMRegisterJump("cmp dword ptr[rip + 48h], 0; jnz A; mov edx, 0x40A00000; movd xmm7, edx; comiss xmm0, xmm7; jb A; ", "addss", "xmm0", "xmm7", "edx", DecreaseFloatPrecision(30.0f / framerate, 23), "jmp B; A: mov edx, 0x3F800000; movd xmm7, edx; addss xmm0, xmm7; B: nop", & encode, & size)) { //The game expects 1.0 increments when deciding what to do next. Unfortunately adding up float values introduces errors that make the strict comparison not match. So round up to either 0.5 or 0.25.
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + 2, match.get_first<void>(0x7 + 0x2e6fc4)); //Third byte of a mov instruction is the address, gets computed so that it points to dword_14065833C
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}


			//Unknown (likely Gameplay fixes #2 due to proximity) [ref: 0x0013D86C]
			match = pattern("00 00 00 F3 0F 10 04 88 F3 0F 5C 05 78 DD 20 00").count(1);
			if (!ModifyXMMRegisterJump("", "subss", "xmm0", "xmm7", "edx", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//Fix controller camera speed (orbital) for controller
			match = pattern("C7 F3 0F 59 C7 0F 28 F8 F3 0F 59 3D AC 2D 32 00").count(1);
			if (!ModifyXMMRegisterJump("mulss xmm7, dword ptr [rip + 0x322dac]", "mulss", "xmm7", "xmm9", "edx", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + 4, match.get_first<void>(0x10 + 0x322dac)); //Fifth byte of a movss x86 is the address, gets computed so that it points to dword_7FF78856141C
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}
			//Same as above but for mouse
			match = pattern("F3 0F 59 3D 9E 2D 32 00 80 3D 0A AA 36 00").count(1);
			if (!ModifyXMMRegisterJump("mulss xmm7, dword ptr [rip + 0x322d9e]", "mulss", "xmm7", "xmm9", "edx", log(framerate)/log(30.0f), "", &encode, &size)) { //Mouse movement doesn't scale linearly, this seems like a good compromise based on a few framerates samples in the three camera speed options available
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + 4, match.get_first<void>(0x8 + 0x322d9e)); //Fifth byte of a movss x86 is the address, gets computed so that it points to dword_7FF788561418
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}
			//Fix controller camera speed (when transitioning to lock-on)
			match = pattern("FF F3 44 0F 10 1D 42 F6 31 00 F3 41 0F 59 C3 44").count(1);
			if (!ModifyXMMRegisterJump("movss xmm11, dword ptr [rip + 0x31f642]", "mulss", "xmm11", "xmm5", "edx", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + 5, match.get_first<void>(0xA + 0x31f642)); //Sixth byte of a movss x64 is the address, gets computed so that it points to dword_7FF78856141C
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xA)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x1), space, PATCH_JUMP);
			}


			//Some other parts of the HUD (i.e heat effect in the main menu) [ref: 0x002E4E50]
			match = pattern("48 8B CB 75 0D 0F 28 D6 F3 0F 59 90 F8 01 00 00").count(1);
			if (!ModifyXMMRegisterJump("", "mulss", "xmm2", "xmm7", "r10d", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//[ref: 0x002A1838]
			match = pattern("E8 3B C3 FF FF F3 41 0F 58 84 3E B8 00 00 00 F3").count(1);
			if (!ModifyXMMRegisterJump("addss xmm0, dword ptr [r14+rdi+0B8h]", "mulss", "xmm0", "xmm7", "r10d", 30.0f / framerate, "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xF)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}

			//Blue wavey effect
			match = pattern("0F 29 B3 28 FF FF FF F3 44 0F 10 2D 55 E5 17 00").count(1);
			if (!LoadXMMRegisterJump("", "xmm13", "edx", DecreaseFloatPrecision(4.0f * (30.0f / framerate), 8), "", &encode, &size)) {
				space = trampoline->RawSpace(size);
				memcpy(space, encode, size);
				ks_free_fnc(encode);
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}
		}
		else {
			MessageBox(
				NULL,
				(LPCWSTR)L"Couldn't locate the required functions in keystone.dll for the framerate patch.\nMake sure you are using the included keystone.dll in this folder from the github release.",
				(LPCWSTR)L"keystone.dll Error",
				MB_ICONWARNING | MB_OK
			);
		}
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(lpvReserved);

	if ( fdwReason == DLL_PROCESS_ATTACH )
	{
		hDLLModule = hinstDLL;
	}
	return TRUE;
}