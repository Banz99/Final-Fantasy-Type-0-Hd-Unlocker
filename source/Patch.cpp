#include "Utils/MemoryMgr.h"
#include "Utils/Patterns.h"

#include <Shlwapi.h>

#include <string_view>
#include <sstream>
#include <regex>
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

Trampoline* trampoline;
float* floatpointers;
const uint8_t ALLOCATED_FLOATS = 30;
const uint8_t CONSTANTS_ARRAY_SIZE = 5;
const uint8_t POINTERS_ARRAY_SIZE = 5;
const uint8_t FLOATS_ARRAY_SIZE = 5;

uintptr_t FindOrInsertFloat(float value)
{
	for (int i = 0; i < ALLOCATED_FLOATS; i++)
	{
		if (floatpointers[i] == 0.0f)
			floatpointers[i] = value;
		if (floatpointers[i] == value)
			return reinterpret_cast<uintptr_t>(&floatpointers[i]);
	}
	return NULL;
}

float DecreaseFloatPrecision(float input, uint8_t nbits)
{
	if (nbits == 0)
		return input;
	uint32_t mask = 0xFFFFFFFF - (static_cast<uint32_t>(pow(2, nbits) - 1));
	uint32_t temp = *reinterpret_cast<uint32_t*>(&input); //Necessary evil bithack that decreases the float's precision. (Only 60 and 120 fps will be 100% correct, every other value will be lower, resulting in a slight speedup or slowdown depending on context)
	temp = temp & mask;
	return *reinterpret_cast<float*>(&temp);
}

int ParametricASMJump(const char* asmstring, std::byte** spaceptr, size_t* size, uint64_t* constants, uintptr_t* pointers, float* param_floats)
{
	size_t count;
	unsigned char* encode;
	uintptr_t totalpointers[POINTERS_ARRAY_SIZE + FLOATS_ARRAY_SIZE]; //Floats gets resolved to a rip offsetted pointer anyway, so create a full list
	size_t relativeoffset = 0;

	memcpy(totalpointers, pointers, POINTERS_ARRAY_SIZE * sizeof(uintptr_t));

	std::string replace_constants = asmstring;
	for (int i = 0; i < CONSTANTS_ARRAY_SIZE; i++) {
		std::regex e("\\$" + std::to_string(i));
		uint64_t rep = constants[i];
		replace_constants = std::regex_replace(replace_constants, e, std::to_string(constants[i])); //Replace constants via regex replace, so there is no need to worry about sizes of the constant itself
	}

	std::string replace_floats = replace_constants;
	std::smatch sm;
	for (int i = 0; i < FLOATS_ARRAY_SIZE; i++) {
		std::regex e("%" + std::to_string(i));
		totalpointers[POINTERS_ARRAY_SIZE + i] = FindOrInsertFloat(param_floats[i]); //Find the float addresses
		replace_floats = std::regex_replace(replace_floats, e, "dword ptr [rip + ?" + std::to_string(POINTERS_ARRAY_SIZE + i) + "]"); //Recreate the rip offset syntax, with range outside of what could be used so it doesn't interfere with user defined ones
	}

	std::istringstream stream(replace_floats);
	std::string s;
	std::string finaloutput = "";
	std::regex x86_jumps("J[A-Z]+[ ]+[A-Z]", std::regex_constants::icase); //A relative crude way to detect "jmp A", "je B", "jb C" etc
	std::regex ripoffset("\\?([0-9]+)");
	while (std::getline(stream, s, ';'))
	{
		if (std::regex_search(s, sm, x86_jumps)) {
			relativeoffset += 2; //Assume the things we patch are small enough so that there aren't 16 bits jumps
			finaloutput += s + ";";
		}
		else
		{
			if (!std::regex_search(s, sm, ripoffset))
			{
				if (ks_asm_fnc(ks, s.c_str(), 0, &encode, size, &count))
					return 1;
				relativeoffset += *size;
				finaloutput += s + ";";
				ks_free_fnc(encode);
			}
			else
			{
				if (ks_asm_fnc(ks, std::regex_replace(s, ripoffset, "0x11223344").c_str(), 0, &encode, size, &count)) {
					#ifdef DEBUG
						const char* instruction = std::regex_replace(s, ripoffset, "0x11223344").c_str()
						DebugBreak();
					#endif
					return 1;
				}
				relativeoffset += *size;
				uint64_t ripoffset_val = totalpointers[std::stoi(sm[1].str())] - (reinterpret_cast<uintptr_t>(trampoline->RawSpace(0)) +relativeoffset); //sm[1] because $0 of a regexp is the entire matched thing
				finaloutput += std::regex_replace(s, ripoffset, std::to_string(ripoffset_val)) + ";";
				ks_free_fnc(encode);
			}
		}
	}

	if (ks_asm_fnc(ks, (finaloutput + "jmp 0x1000000;").c_str(), 0, &encode, size, &count)) {
		#ifdef DEBUG
			const char* full_asm_out = finaloutput.c_str();
			DebugBreak();
		#endif
		return 1;
	}
	*spaceptr = trampoline->RawSpace(*size);
	memcpy(*spaceptr, encode, *size);
	ks_free_fnc(encode);
	return 0;
}

//This defines a spline that interpolates the original "FF F0 C0 B0 A0 80 70 60" sequence of bytes used when defining the pulsating transparency (in a 0.0 -> 1.0 range)
uint8_t TransparencySplineInterpolation(float x)
{
	if (x < 0.14)
		return round(-3785.14 * pow(x, 3) - 27.75 * x + 255);
	if (x < 0.29)
		return round(7606.68 * pow(x, 3) - 4882.21 * pow(x, 2) + 669.71 * x + 221.79);
	if (x < 0.43)
		return round(-4346.59 * pow(x, 3) + 5363.45 * pow(x, 2) - 2257.63 * x + 500.58);
	if (x < 0.57)
		return round(-1196.32 * pow(x, 3) + 1313.1 * pow(x, 2) - 521.76 * x + 252.6);
	if (x < 0.71)
		return round(3643.86 * pow(x, 3) - 6984.34 * pow(x, 2) + 4219.64 * x - 650.52);
	if (x < 0.86)
		return round(-2403.12 * pow(x, 3) + 5973.47 * pow(x, 2) - 5035.95 * x + 1553.19);
	else return round(480.62 * pow(x, 3) - 1441.87 * pow(x, 2) + 1320.06 * x - 262.82);
}

//Honestly, I have no idea why Square Enix thought that the blinking yellow arrow should have different values when in battle, but here we are (a spline for this doesn't produce a great result)
uint8_t TransparencyLinearInterpolation(float x) {
	if (x < 0.52)
		return round(432.69 * x + 25);
	if (x < 0.68)
		return 250;
	else return round(-703.125 * x + 728.125);
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

		float aspect_ratio = static_cast<float>(ResX) / static_cast<float>(ResY);

		if (aspect_ratio != 16.0f / 9.0f) //See below
		{
			auto geometry_aspect_ratio = pattern("00 C7 87 74 08 00 00 39 8E E3 3F C7 87 50 06 00").count(1); //This is not a FOV slider, it just rescales the geometry so that it isn't stretched in the viewport, like the HUD
			if (geometry_aspect_ratio.size() == 1)
			{
				Patch<float>(geometry_aspect_ratio.get_first<void>(0x7), aspect_ratio);
			}

			auto res_mismatch_fix = pattern("00 00 00 4C 8D 05 C6 B5 5E 00 48 8D 15 AF B5 5E").count(1); //This fix seems to have the side effect of scaling the HUD via nearest neighbor, which isn't really ideal and shouldn't be engaged when the aspect ratio is already 16:9, hence the check above
			if (res_mismatch_fix.size() == 1)
			{
				Patch<int8_t>(res_mismatch_fix.get_first<void>(0x6), 0xB6);
			}
		}
	}

	hDLLKeystone = LoadLibrary(L"keystone.dll");

	ks_open_fnc = (ks_open_dll)GetProcAddress(hDLLKeystone, "ks_open");
	ks_asm_fnc = (ks_asm_dll)GetProcAddress(hDLLKeystone, "ks_asm");
	ks_free_fnc = (ks_free_dll)GetProcAddress(hDLLKeystone, "ks_free");

	if (ks_open_fnc && ks_asm_fnc && ks_free_fnc)
	{

		ks_open_fnc(KS_ARCH_X86, KS_MODE_64, &ks);

		trampoline = Trampoline::MakeTrampoline(GetModuleHandle(nullptr));
		uintptr_t baseaddress = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
		size_t size = 0;
		std::byte* space;
		floatpointers = reinterpret_cast<float*>(trampoline->RawSpace(ALLOCATED_FLOATS * sizeof(float)));
		memset(floatpointers, 0, ALLOCATED_FLOATS * sizeof(float));
		uint64_t constants[CONSTANTS_ARRAY_SIZE]; //marked in ASM with $x
		uintptr_t pointers[POINTERS_ARRAY_SIZE]; //marked in ASM with ?x
		float param_floats[FLOATS_ARRAY_SIZE]; //marked in ASM with %x
		auto match = pattern("");

		const int framerateint = GetPrivateProfileIntW(L"OverrideFramerate", L"FpsCap", 0, wcModulePath);

		if (framerateint > 30)
		{
			float framerate = framerateint;
			if (framerate > 120.0f)
			{
				MessageBox(
					NULL,
					(LPCWSTR)L"Due to technical limitations, the framerate of the game cannot exceed 120fps.\nTo make this message disappear on startup, lower the value in FFT0HD Unlocker.ini.\nThe game will now start with a 120fps cap.",
					(LPCWSTR)L"Framerate Warning",
					MB_ICONWARNING | MB_OK
				);
				framerate = 120.0f;
			}

			/*[ref] points to the absolute address in the PSP elf on which similar patches were applied*/

			//Actual value used for the frame limiter (also likely to [ref: 0x0008614C] since there are no other 0.0333333 floats referenced in the code)
			auto frameratelimit = pattern("88 88 08 3D 89 88 08 3D 35 FA 0E 3D 29 5C 0F 3D").count(1);
			Patch<float>(frameratelimit.get_first<void>(0x4), 1.0f / framerate);
			DWORD dwProtect;
			VirtualProtect(frameratelimit.get_first<void>(0x4), sizeof(float), PAGE_EXECUTE_READWRITE, &dwProtect); //This variable needs to be writable by the movie function below

			//Framerate here is used as an integer
			//[ref: 0x0004F084]
			auto frint1 = pattern("88 42 30 B0 01 C3 04 1E 88 42 30 32 C0 C3 CC").count(1);
			Patch<uint8_t>(frint1.get_first<void>(0x7), framerate);
			//[ref: 0x00179AEC]
			auto frint2 = pattern("05 7F 4A 3E 00 83 F8 1E 7C 23 C7 05 70 4A 3E").count(1);
			Patch<uint8_t>(frint2.get_first<void>(0x7), framerate);
			//[ref: 0x00208D84] Maybe fixes some timers?
			auto frint3 = pattern("51 01 00 00 81 BB 70 6E 00 00 84 03 00 00 0F 8E").count(1);
			Patch<uint32_t>(frint3.get_first<void>(0xA), framerate * 30);
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
			Patch<uint8_t>(frint5.get_first<void>(0xB), (framerate / 30.0f) * 20.0f);
			frint5 = pattern("D1 73 43 41 FF 40 08 41 83 78 08 14 7C 66 83 F8").count(1);
			Patch<uint8_t>(frint5.get_first<void>(0xB), (framerate / 30.0f) * 20.0f);
			//Flashing examine button
			auto frint6 = pattern("DB 78 4E 8B 4D CB FF C9 75 47 2B FA 83 FB 14 7C").count(1);
			Patch<uint8_t>(frint6.get_first<void>(0xE), (framerate / 30.0f) * 20.0f);
			frint6 = pattern("00 69 C9 00 00 00 0D 2B C1 EB 24 83 FB 0A 7D 11").count(1);
			Patch<uint8_t>(frint6.get_first<void>(0x6), 255.0f / ((framerate / 30.0f) * 19.0f)); //0x0D000000 is a uint32_t but the only relevant part are the highest 8 bits (0D) since it's used to calculate the alpha channel.
			Patch<uint8_t>(frint6.get_first<void>(0xD), (framerate / 30.0f) * 10.0f);
			frint6 = pattern("8B CB B8 00 00 00 FF 69 C9 00 00 00 0D 2B C1 EB").count(1);
			Patch<uint8_t>(frint6.get_first<void>(0xC), 255.0f / ((framerate / 30.0f) * 19.0f));
			frint6 = pattern("0E 8B C3 69 C0 00 00 00 0D 81 C7 00 00 00 FB 03").count(1);
			Patch<uint8_t>(frint6.get_first<void>(0x8), 255.0f / ((framerate / 30.0f) * 19.0f));
			//Random encounters timer
			auto frint7 = pattern("00 00 C7 83 68 6E 00 00 2C 01 00 00 E8 CF 8E EF").count(1);
			Patch<uint32_t>(frint7.get_first<void>(0x8), framerate * 10);
			//SP support timers
			auto frint8 = pattern("00 00 00 4C 89 53 08 6B C0 1E 89 43 04 48 8B 5C").count(1);
			Patch<uint8_t>(frint8.get_first<void>(0x9), framerate);
			//Minimap popup delay in the upper right corner when an area text is being shown (on the field)
			auto frint9 = pattern("8B 05 8A A9 1F 00 B9 AA 00 00 00 3B EE 0F 4C C1").count(1);
			Patch<uint32_t>(frint9.get_first<void>(0x7), (framerate / 30.0f) * 170.0f);
			//RTS turret
			auto frint10 = pattern("00 00 B8 3C 00 00 00 66 89 87 D4 01 00 00 B8 02").count(1);
			Patch<uint32_t>(frint10.get_first<void>(0x3), ((framerate * 2.0f - 30.0f) / 30.0f) * 60.0f); //Also take into consideration the time for moving down
			frint10 = pattern("1D B8 06 00 00 00 66 89 B7 C8 01 00 00 66 89 87").count(1);
			Patch<uint32_t>(frint10.get_first<void>(0x2), (framerate / 30.0f) * 6.0f);
			frint10 = pattern("E2 7E 06 41 83 EE 02 EB 06 41 BE E2 FF FF FF 45").count(1);
			Patch<int8_t>(frint10.get_first<void>(), (framerate / 30.0f) * -30.0f);
			Patch<int32_t>(frint10.get_first<void>(0xB), (framerate / 30.0f) * -30.0f);
			frint10 = pattern("41 83 FD 02 0F 87 AA 03 00 00 41 83 FE E2 0F 85").count(1);
			Patch<int8_t>(frint10.get_first<void>(0xD), (framerate / 30.0f) * -30.0f);
			//RTS Fort reshooting time
			auto frint11 = pattern("FF FF E8 D9 6C FF FF B8 64 00 00 00 66 89 86 C2").count(1);
			Patch<uint32_t>(frint11.get_first<void>(0x8), (framerate / 30.0f) * 100.0f);
			//RTS MP regen interval near Fort
			auto frint12 = pattern("D0 E8 22 6A D4 FF B8 19 00 00 00 66 89 83 BE 01").count(1);
			Patch<uint32_t>(frint12.get_first<void>(0x7), (framerate / 30.0f) * 25.0f);

			//[ref: 0x000A9AF4]
			auto charactersanimationspeed = pattern("80 A3 B6 09 00 00 F7 C7 83 D8 05 00 00 00 00 80 3F");
			Patch<float>(charactersanimationspeed.get_first<void>(0xD), framerate != 60.0f ? 30.0f / framerate : 29.9f / framerate); //The lip sync function that the game uses for real time cutscenes REALLY doesn't like 0.5f as a value here.

			//Always use in conjunction with $ or damage will be registered multiple times
			auto rtsanimationspeed = pattern("85 D2 74 0A C7 82 0C 06 00 00 00 00 80 3F 48 83").count(1);
			Patch<float>(rtsanimationspeed.get_first<void>(0xA), 30.0f / framerate);

			//Relock the game back to 30fps when prerendered cutscenes are playing (and unlock it again if needed when the skip cutscene menu shows up so it isn't slowed down (it still is when fading out, can't change that or audio would get out of sync))
			auto movielimit = pattern("02 32 C9 48 8B 05 7E F9 60 00 88 88 D0 00 00 00").count(1);
			float inv_framerate = 1.0f / framerate;
			constants[0] = *reinterpret_cast<uint32_t*>(&inv_framerate); //(0x3D088889 is 1.0/30.0)
			pointers[0] = baseaddress + 0x75B7CC; //(1 when the skip cutscene menu is showing, 0 otherwise)
			pointers[1] = frameratelimit.get(0).get_uintptr(0x4);
			if (!ParametricASMJump("mov [rax + 0xD0], cl; cmp cl, 0; je A; cmp dword ptr [rip + ?0], 1; je A; mov dword ptr [rip + ?1], 0x3D088889; jmp B; A: mov dword ptr [rip + ?1], $0; B: nop", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, movielimit.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(movielimit.get_first<void>(0xA), space, PATCH_JUMP);
			}

			//Characters walking speeds (with check for cutscenes) [ref: 0x00083CF8]
			match = pattern("24 0F 28 CE F3 0F 59 4C 24 20 F3 0F 11 43 1C F3").count(1);
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x658F70;
			pointers[1] = baseaddress + 0x6D1CEC;
			if (!ParametricASMJump("mulss xmm1, dword ptr [rsp + 0x20]; cmp dword ptr [rip + ?0], 1; jnz A; cmp dword ptr [rip + ?1], 0; jnz B; A: movss xmm7, %0; mulss xmm1, xmm7; mulss xmm6, xmm7; B: nop", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xA)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}

			//Controlled character turning speed (a bit broken above 90 fps) [ref: 0x00006734 to 0x00006744]
			match = pattern("F3 0F 59 49 40 F3 0F 59 CA F3 0F 59 51 34 F3 0F 59 0D 1F C4 3A 00").count(1);
			param_floats[0] = 15.0f / framerate;
			if (!ParametricASMJump("movss xmm1, dword ptr [rcx + 0x40]; movss xmm2, dword ptr [rcx + 0x34]; mulss xmm1, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x16)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}

			//First cutscene slow-motion walk speed [ref: 0x00006998]
			match = pattern("20 5B C3 F3 0F 10 41 04 F3 0F 58 05 69 BE 3A 00").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("addss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//Camera distance in the first cutscene [ref: 0x00155CB0]
			match = pattern("00 44 0F 29 44 24 70 F3 44 0F 10 05 DC BF 29 00").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("movss xmm8, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}

			//Fix camera movement in the panning cutscenes (i.e new area introductions in Akademia)
			match = pattern("0F 85 E9 01 00 00 8B 05 94 51 37 00 FF C0 2B C8").count(1);
			param_floats[0] = framerate / 30.0f;
			pointers[0] = baseaddress + 0x658FA8;
			if (!ParametricASMJump("mov eax, dword ptr [rip + ?0]; cvtsi2ss xmm11, ecx; mulss xmm11, %0; cvtss2si ecx, xmm11;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x6), space, PATCH_JUMP);
			}
			//Fix camera rotation in the panning cutscenes (i.e new area introductions in Akademia)
			match = pattern("00 8B 05 7D 4D 37 00 FF C0 2B C8 89 05 73 4D 37").count(1);
			param_floats[0] = framerate / 30.0f;
			pointers[0] = baseaddress + 0x658FAC;
			if (!ParametricASMJump("mov eax, dword ptr [rip + ?0]; cvtsi2ss xmm11, ecx; mulss xmm11, %0; cvtss2si ecx, xmm11;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x7)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x1), space, PATCH_JUMP);
			}

			//Various timings, used mainly in cutscenes but not exclusively, with a specific fix for Akademia teleporters slowdown (why did you do this, Square Enix...) [ref: 0x00127D90]
			match = pattern("2F C8 76 04 C6 41 2C 01 F3 0F 5C 0D 93 34 22 00").count(1);
			constants[0] = baseaddress + 0x37F439;
			constants[1] = baseaddress;
			param_floats[0] = 30.0f / framerate;
			param_floats[1] = 1.0f;
			pointers[0] = baseaddress + 0x658F70;
			if (!ParametricASMJump("mov r13, $0; cmp r13, qword ptr [rsp]; jne A; mov r13, $1; cmp r11, r13; jne A; cmp dword ptr [rip + ?0], 0; je B; A: subss xmm1, %0; jmp C; B: subss xmm1, %1; C: nop", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//Part of the HUD [ref: 0x002491E4]
			match = pattern("0F 5B C0 F3 0F 5E C8 F3 0F 58 CA 41 0F 2F CF").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("divss xmm1, xmm0; mulss xmm1, %0; addss xmm1, xmm2", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xB)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x3), space, PATCH_JUMP);
			}

			//[ref: 0x001F9924 and 0x001F9934]
			match = pattern("05 57 A6 24 00 F3 41 0F 59 C8 D1 E8 41 84 C7 74").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("mulss xmm1, xmm8; mulss xmm1, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xA)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}

			//Gameplay fixes #1 (i.e guards falling into the ground below when dropping from the ship at the beginning of the game) [ref: 0x0013D75C, different approach used]
			match = pattern("F3 0F 58 05 3C DE 20 00 F3 0F 11 04 88 0F 28 C2").count(1);
			auto lastincrement = trampoline->Pointer<float>();
			*lastincrement = -1.0;
			pointers[0] = reinterpret_cast<uintptr_t>(lastincrement);
			if (!ParametricASMJump("movss dword ptr [rip + ?0], xmm0; movss dword ptr [rax + rcx * 4], xmm0;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xD)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}
			match = pattern("28 C8 F3 0F 11 4D 18 45 84 C0 0F 84 C9 00 00 00").count(1);
			param_floats[0] = framerate / 30.0f;
			param_floats[1] = 5.0f;
			pointers[0] = reinterpret_cast<uintptr_t>(lastincrement);
			if (!ParametricASMJump("movss dword ptr [rbp + 0x18], xmm1; cmp dword ptr [rdi], 4; jz B; cmp r11d, 0x6d; jne B; comiss xmm1, dword ptr [rip + ?0]; jne B; comiss xmm3, %1; jbe B; mulss xmm3, %0; cvtss2si eax, xmm3; cvtsi2ss xmm3, eax; B: movss dword ptr [rbp + 0x30], xmm3;", &space, &size, constants, pointers, param_floats)) //If the switch will go to case 109 (cmp r11d, 0x6d), and the value in xmm1 has been retrieved via baseaddress + 0x372150() (it didn't follow the branch of cmp dword ptr [rdi], 4), then check if it's the last incremented value. If that's the case then it means that gets compared to xmm3 for triggering frame counter based events, so adjust (and truncate) xmm3 accordingly. Check for <= 5.0 to avoid softlocks.
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x7)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x2), space, PATCH_JUMP);
			}

			//Unknown (likely Gameplay fixes #2 due to proximity) [ref: 0x0013D86C]
			match = pattern("00 00 00 F3 0F 10 04 88 F3 0F 5C 05 78 DD 20 00").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("subss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//Fix controller camera speed (orbital) for controller
			match = pattern("C7 F3 0F 59 C7 0F 28 F8 F3 0F 59 3D AC 2D 32 00").count(1);
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x61141C;
			if (!ParametricASMJump("mulss xmm7, dword ptr [rip + ?0]; mulss xmm7, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}
			//Same as above but for mouse
			match = pattern("F3 0F 59 3D 9E 2D 32 00 80 3D 0A AA 36 00").count(1);
			param_floats[0] = log(framerate)/log(30.0f);
			pointers[0] = baseaddress + 0x611418;
			if (!ParametricASMJump("mulss xmm7, dword ptr [rip + ?0]; mulss xmm7, %0", &space, &size, constants, pointers, param_floats)) //Mouse movement doesn't scale linearly, this seems like a good compromise based on a few framerates samples in the three camera speed options available
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}
			//Fix controller camera speed (when transitioning to lock-on)
			match = pattern("FF F3 44 0F 10 1D 42 F6 31 00 F3 41 0F 59 C3 44").count(1);
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x61141C;
			if (!ParametricASMJump("movss xmm11, dword ptr [rip + ?0]; mulss xmm11, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xA)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x1), space, PATCH_JUMP);
			}

			//Cycling 2d elements speed (i.e heat particles in the main menu, fire textures etc.) [ref: 0x002E4E50]
			match = pattern("48 8B CB 75 0D 0F 28 D6 F3 0F 59 90 F8 01 00 00").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("mulss xmm2, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//Main menu delay frames before showing the intro cutscene again
			match = pattern("00 48 8B 8C 24 40 1A 00 00 48 33 CC E8 FF 7D EE").count(1);
			param_floats[0] = framerate / 30.0f;
			if (!ParametricASMJump("mov ecx, dword ptr [rbx + 0x11C]; cvtsi2ss xmm10, ecx; mulss xmm10, %0; cvtss2si ecx, xmm10; mov dword ptr [rbx + 0x11C], ecx; mov rcx, qword ptr [rsp + 0x1a40]", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x9)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x1), space, PATCH_JUMP);
			}

			//[ref: 0x002A1838]
			match = pattern("E8 3B C3 FF FF F3 41 0F 58 84 3E B8 00 00 00 F3").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("addss xmm0, dword ptr [r14 + rdi + 0xB8]; mulss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xF)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}

			//Blue wavey effect
			match = pattern("0F 29 B3 28 FF FF FF F3 44 0F 10 2D 55 E5 17 00").count(1);
			param_floats[0] = DecreaseFloatPrecision(4.0f * (30.0f / framerate), 8);
			if (!ParametricASMJump("movss xmm13, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}

			//Moogle dialog box
			match = pattern("39 83 5C 01 00 00 40 0F B6 FF B9 01 00 00 00 0F").count(1);
			param_floats[0] = framerate / 30.0f;
			if (!ParametricASMJump("cvtsi2ss xmm11, eax; mulss xmm11, %0; cvtss2si eax, xmm11; cmp [rbx + 0x15C], eax", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x6)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}

			//Delay before next dialog when characters speak via the COM (i.e Kurasame at the beginning, with subtitles shown on the left side) Note: if you liked the previous speeded up behaviour you can select the fast dialog speed inside the options.
			match = pattern("0F 4F C1 89 45 0C 48 8B 5C 24 58 48 8B 6C 24 68").count(1);
			param_floats[0] = framerate / 30.0f;
			if (!ParametricASMJump("cmovg eax, ecx; cvtsi2ss xmm11, eax; mulss xmm11, %0; cvtss2si eax, xmm11; mov [rbp + 0xC], eax", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x6)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}

			//In game timer shown in Akademia (it's a frame counter)
			match = pattern("33 FF 45 33 C0 F7 25 ED 7B 2A 00 8B FA B8 89 88").count(1);
			param_floats[0] = 15.0f / framerate;
			pointers[0] = baseaddress + 0x6BEE88;
			if (!ParametricASMJump("mul dword ptr [rip + ?0]; cvtsi2ss xmm11, edx; mulss xmm11, %0; cvtss2si edx, xmm11;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xB)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}
			//In game timer when loaded from save file (for consistency between framerates, otherwise the division above while timed correctly, would have been offsetted, basically (![X]*speed!+[Y*2]*speed)/speed so that whatever increased speed is there, it's cancelled out (this is the between !! part))
			match = pattern("0F 85 87 00 00 00 B9 BA 00 00 00 0F 1F 44 00 00 0F 28 00 4D 8D 89 80 00 00 00 48 8D 80 80 00 00 00 41 0F 29 41 80").count(1); //this pattern sucks
			constants[0] = baseaddress + 0x6BEE80 + 0x80;
			param_floats[0] = framerate / 15.0f;
			if (!ParametricASMJump("movaps xmmword ptr [r9 - 0x80], xmm0; mov r15, $0; cmp r9, r15; jnz A; cvtsi2ss xmm11, dword ptr [r9 - 0x78]; mulss xmm11, %0; cvtss2si r15d, xmm11; mov dword ptr [r9 - 0x78], r15d; A: nop", &space, &size, constants, pointers, param_floats)) //The game uses a weird way of loading the save file, it copies multiple values via xmmword even though they are dwords, check if baseaddress + 0x6BEE88 had been written (via 256 bit write from 0x6BEE80) and modify it
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x26)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x21), space, PATCH_JUMP);
			}
			//Game timer when saved to the sysfile (offset 0x8 for TYPE0SYS in SYSTEMDATA (which is a memmove starting from 0x1406BEE80))
			match = pattern("BC 97 09 00 48 8B 0D 65 0D 70 00 48 83 C1 08 E8").count(1);
			constants[0] = baseaddress + 0x6BEE80;
			param_floats[0] = 15.0f / framerate;
			pointers[0] = baseaddress + 0x77EC10;
			if (!ParametricASMJump("mov rcx, qword ptr [rip + ?0]; mov r9, $0; cmp r15, r9; jnz A; cvtsi2ss xmm11, dword ptr [rdi + 0x8]; mulss xmm11, %0; cvtss2si r9d, xmm11; and r9d, 0xFFFFFFFE; mov dword ptr [rdi + 0x8], r9d; A: nop", &space, &size, constants, pointers, param_floats)) //The AND is just a failsafe, maybe not strictly necessary, but since the frame counter gets incremented by 2 every frame, having an odd number of them may cause problems.
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xB)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}
			//Game timer when copied into a buffer for writing it into the various save data slots
			match = pattern("7C 5E 4C 00 89 87 64 07 00 00 0F B6 05 67 BC 4C").count(1);
			param_floats[0] = 15.0f / framerate;
			if (!ParametricASMJump("cvtsi2ss xmm11, eax; mulss xmm11, %0; cvtss2si eax, xmm11; and eax, 0xFFFFFFFE; mov [rdi + 0x764], eax", &space, &size, constants, pointers, param_floats)) //The AND is just a failsafe, maybe not strictly necessary, but since the frame counter gets incremented by 2 every frame, having an odd number of them may cause problems.
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xA)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}

			//Icons on the minimap that blink
			match = pattern("00 89 45 A0 81 E1 0F 00 00 80 7D 07 FF C9 83 C9 F0 FF C1 48 63 C1 48 8D 55 88 48 8B CB 44 8B 74 85 00 48").count(1);
			uint32_t transparency_frames_count = 16.0f * framerate / 30.0f;
			transparency_frames_count &= 0xFFFFFFFE; //This has to be an even number
			auto transparency_frames = trampoline->RawSpace(transparency_frames_count);
			for (uint32_t i = 0; i < transparency_frames_count / 2; i++)
			{
				transparency_frames[i] = static_cast<std::byte>(TransparencySplineInterpolation(static_cast<float>(i) / (transparency_frames_count / 2 - 1)));
				transparency_frames[transparency_frames_count - 1 - i] = transparency_frames[i];
			}
			constants[0] = transparency_frames_count;
			pointers[0] = reinterpret_cast<uintptr_t>(transparency_frames);
			if (!ParametricASMJump("mov eax, ecx; mov r14d, $0; xor edx, edx; div r14d; lea rax, [rip + ?0]; add rax, rdx; xor ecx, ecx; mov cl, byte ptr [rax]; mov r14d, ecx; lea rdx, [rbp - 0x78]; mov rcx, rbx;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x22)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}
			//Handle edge case that works differently for some reason (26 frames of animation instead of 16)
			match = pattern("0D D3 97 1A 00 45 69 C9 00 00 00 19 41 81 C9 FF").count(1);
			transparency_frames_count = 26.0f * framerate / 30.0f;
			transparency_frames = trampoline->RawSpace(transparency_frames_count);
			for (uint32_t i = 0; i < transparency_frames_count; i++)
			{
				transparency_frames[i] = static_cast<std::byte>(TransparencyLinearInterpolation(static_cast<float>(i) / (transparency_frames_count - 1)));
			}
			constants[0] = transparency_frames_count;
			pointers[0] = baseaddress + 0x63CD00;
			pointers[1] = reinterpret_cast<uintptr_t>(transparency_frames);
			if (!ParametricASMJump("mov eax, dword ptr [rip + ?0]; mov r9d, $0; xor edx, edx; div r9d; lea rax, [rip + ?1]; add rax, rdx; mov dl, byte ptr [rax]; mov r9d, edx; shl r9d, 0x18; mov edx, dword ptr [rsp + 0x120];", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}
			match = pattern("6C 94 1A 00 45 69 C0 00 00 00 19 41 81 C8 FF FF").count(1); //Also handle the else branch
			if (!ParametricASMJump("mov eax, dword ptr [rip + ?0]; mov r9d, $0; xor edx, edx; div r9d; lea rax, [rip + ?1]; add rax, rdx; mov dl, byte ptr [rax]; mov r9d, edx; shl r9d, 0x18; mov edx, dword ptr [rsp + 0x120];", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}

			//Color circles pulsating (TODO: Understand how they work and patch them instead of making them pretend they're running @30fps)
			match = pattern("83 F8 01 41 B0 01 B8 89 88 88 88 75 0C 45 8D 4B").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("mov eax, 0x88888889; cvtsi2ss xmm11, r11d; mulss xmm11, %0; cvtss2si r11d, xmm11", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xB)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x6), space, PATCH_JUMP);
			}

			//Fix animated water texture speed
			match = pattern("F3 44 0F 59 15 4F DA 1B 00 0F 28 D1 85 C9 0F 84").count(1);
			param_floats[0] = (0.033333331f * 30.0f) / framerate;
			if (!ParametricASMJump("mulss xmm10, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x9)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}

			//Fix info panels on the left side of the screen disappearing too quickly (i.e Character used Magic, Obtained Phantoma etc.)
			match = pattern("4C 8D 34 90 8B 55 80 85 D2 41 C6 46 1A 00 41 0F").count(1);
			param_floats[0] = framerate / 30.0f;
			if (!ParametricASMJump("mov edx, dword ptr [rbp - 0x80]; cvtsi2ss xmm11, edx; mulss xmm11, %0; cvtss2si edx, xmm11; test edx, edx;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x9)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}

			//Projectile speed general fix (This is the holy grail of fixes, but it's also one of the worst manual x86 code ever written.) Note: the first parameter passed to the function in which this is injected (sub_140287C20) gets copied to rdi. Rdi + 0x54, 58 and 5C contains the coordinate offset for the next frame, which I'd need to adjust according to the framerate, however since the functions that call this one are many and different between each other, the compiler decided to sometimes have temporary registers that holds those values (3 of the registers in the xmm6-12 range) and sometimes reload them from memory. This code should handle every possible combination of those, but it's really ugly. The only other solution would be to manually patch each function before the call, but that would require a lot of redirections for doing basically the same things.
			match = pattern("7A B0 01 4C 8D 9C 24 C0 00 00 00 49 8B 5B 38 49 8B 73 40 49 8B 7B 48 41 0F 28 73 F0 41 0F 28 7B").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("movaps xmm6, xmmword ptr [r11 - 0x10]; movaps xmm7, xmmword ptr [r11 - 0x20]; movaps xmm8, xmmword ptr [r11 - 0x30]; movss xmm2, %0; comiss xmm6, dword ptr [rdi + 0x54]; je A; comiss xmm6, dword ptr [rdi + 0x58]; je A; comiss xmm6, dword ptr [rdi + 0x5C]; jne B; A: mulss xmm6, xmm2; B: comiss xmm7, dword ptr [rdi + 0x54]; je C; comiss xmm7, dword ptr [rdi + 0x58]; je C; comiss xmm7, dword ptr [rdi + 0x5C]; jne D; C: mulss xmm7, xmm2; D: comiss xmm8, dword ptr [rdi + 0x54]; je E; comiss xmm8, dword ptr [rdi + 0x58]; je E; comiss xmm8, dword ptr [rdi + 0x5C]; jne F; E: mulss xmm8, xmm2; F: comiss xmm9, dword ptr [rdi + 0x54]; je G; comiss xmm9, dword ptr [rdi + 0x58]; je G; comiss xmm9, dword ptr [rdi + 0x5C]; jne H; G: mulss xmm9, xmm2; H: comiss xmm10, dword ptr [rdi + 0x54]; je I; comiss xmm10, dword ptr [rdi + 0x58]; je I; comiss xmm10, dword ptr [rdi + 0x5C]; jne J; I: mulss xmm10, xmm2; J: comiss xmm11, dword ptr [rdi + 0x54]; je K; comiss xmm11, dword ptr [rdi + 0x58]; je K; comiss xmm11, dword ptr [rdi + 0x5C]; jne L; K: mulss xmm11, xmm2; L: comiss xmm12, dword ptr [rdi + 0x54]; je M; comiss xmm12, dword ptr [rdi + 0x58]; je M; comiss xmm12, dword ptr [rdi + 0x5C]; jne N; M: mulss xmm12, xmm2; N: movss xmm3, dword ptr [rdi + 0x54]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x54], xmm3; movss xmm3, dword ptr [rdi + 0x58]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x58], xmm3; movss xmm3, dword ptr [rdi + 0x5C]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x5C], xmm3; mov rdi, [r11 + 0x48];", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x26)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x13), space, PATCH_JUMP);
			}

			//New setup for frame counter based fixes
			match = pattern("48 89 3B C6 43 08 01 48 8B 5C 24 40 48 83 C4 20").count(1);
			auto interleavedincrement = trampoline->Pointer<float>();
			auto propagatecounters = trampoline->Pointer<uint8_t>();
			auto reset_list = trampoline->Pointer<uint8_t>(); //Used as an interleaved cycle, to avoid desync
			*reset_list = 1;
			uint8_t sub_14025FD20_rbx_list_count = 10;
			auto sub_14025FD20_rbx_list = reinterpret_cast<uint64_t*>(trampoline->RawSpace(sub_14025FD20_rbx_list_count * sizeof(uint64_t)));
			constants[0] = sub_14025FD20_rbx_list_count;
			param_floats[0] = 30.0f / framerate;
			param_floats[1] = 1.0f;
			pointers[0] = reinterpret_cast<uintptr_t>(interleavedincrement);
			pointers[1] = reinterpret_cast<uintptr_t>(propagatecounters);
			pointers[2] = reinterpret_cast<uintptr_t>(reset_list);
			pointers[3] = reinterpret_cast<uintptr_t>(sub_14025FD20_rbx_list);
			if (!ParametricASMJump("movss xmm2, dword ptr [rip + ?0]; addss xmm2, %0; comiss xmm2, %1; mov byte ptr [rip + ?1], 0; jb A; subss xmm2, %1; mov byte ptr [rip + ?1], 1; neg byte ptr [rip + ?2]; js A; lea rax, [rip + ?3]; xor rbx, rbx; B: mov qword ptr [rax + rbx * 8], 0; inc rbx; cmp bl, $0; jl B; A: movss dword ptr [rip + ?0], xmm2; mov rbx, qword ptr [rsp + 0x40]", &space, &size, constants, pointers, param_floats)) //Use a slightly convoluted way to decide if this rendered frame will update counters (done immediately after renderer sleep)
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}

			//$ Fire projectile damage trigger to rts elements only once
			match = pattern("40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 18 FE FF FF 48 81 EC").count(1);
			pointers[0] = reinterpret_cast<uintptr_t>(sub_14025FD20_rbx_list);
			pointers[1] = reinterpret_cast<uintptr_t>(reset_list);
			if (!ParametricASMJump("lea rax, [rip + ?0]; xor r10, r10; B: cmp qword ptr [rax + r10 * 8], 0; je A; cmp rbx, qword ptr [rax + r10 * 8]; je C; inc r10; jmp B; C: mov eax, 1; ret; A: mov byte ptr [rip + ?1], 1; mov qword ptr [rax + r10 * 8], rbx; push rbp; push rbx; push rsi; push rdi;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x5)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}

			//RTS missions bases regen speed
			match = pattern("00 FF C1 48 85 C0 75 08 8B 96 0C 02 00 00 EB 06").count(1);
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			if (!ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; inc ecx; A: test rax, rax;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x6)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x1), space, PATCH_JUMP);
			}
			//RTS missions troop respawn time
			match = pattern("00 00 66 85 C0 7E 0A 66 FF C8 66 89 86 BC 01 00").count(1);
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			if (!ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; dec ax; A: mov [rsi + 0x1BC], ax;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x11)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}
			//RTS requests countdown
			match = pattern("88 1F 05 00 00 FF C8 41 0F 48 C4 89 85 A0 00 00").count(1);
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			if (!ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; dec eax; A: test eax, eax; cmovs eax, r12d;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xB)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}
			//RTS Troop reshooting time
			match = pattern("7E 22 66 FF C9 66 89 8B D8 01 00 00 0F BF C1 74").count(1);
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			if (!ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; dec cx; A: mov [rbx + 0x1D8], cx;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x2), space, PATCH_JUMP);
			}
			match = pattern("66 FF C8 66 89 83 D8 01 00 00 98 0F 85 BD 03 00").count(1);
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			if (!ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; dec ax; A: mov [rbx + 0x1D8], ax;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xA)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}
			//RTS Projectile duration
			match = pattern("F0 66 89 B3 BC 01 00 00 48 8B 87 A0 01 00 00 48").count(1);
			param_floats[0] = framerate / 30.0f;
			if (!ParametricASMJump("cvtsi2ss xmm11, esi; mulss xmm11, %0; cvtss2si esi, xmm11; mov [rbx + 0x1BC], si", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x1), space, PATCH_JUMP);
			}
			match = pattern("66 0F 6E C0 0F 5B C0 0F 2F 05 1E 9E 12 00 76 1E").count(1);
			param_floats[0] = (framerate / 30.0f) * 40.0f;
			if (!ParametricASMJump("movss xmm10, %0; comiss xmm0, xmm10", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xE)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}
			//$ Fire projectile damage trigger to player/ai enemies only once (fixes Deuce's sphere from being incredibly OP, between other things)
			match = pattern("48 85 D2 0F 84 B6 02 00 00 56 57 41 57 48 81 EC").count(1);
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			if (!ParametricASMJump("test rdx, rdx; jnz A; ret; A: cmp byte ptr [rip + ?0], 1; je B; ret; B: nop", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x9)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}

			//2d mouth texture and eyes blinking timings
			match = pattern("40 53 48 83 EC 30 48 8B 81 30 05 00 00 48 8B D9").count(1);
			pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
			if (!ParametricASMJump("cmp byte ptr [rip + ?0], 1; je A; ret; A: push rbx; sub rsp, 0x30", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x6)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}

			//General frame counter based actions #1 (bullets range (Ace's cards, rocket launcher guy), charged attacks, Nine's jump etc.)
			pattern("66 FF ? 86 00 00 00").for_each_result([framerate, propagatecounters, constants, pointers, param_floats] (auto found)
			mutable {
				size_t size;
				std::byte* space;
				pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
				if (!ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; inc word ptr [rdi + 0x86]; A: nop", &space, &size, constants, pointers, param_floats))
				{
					Patch<uint8_t>(space + 11, *found.get<uint8_t>(2));
					WriteOffsetValue(space + size - 4, found.get<void>(0x7)); //Fill the final jump with the correct address
					InjectHook(found.get<void>(), space, PATCH_JUMP);
				}
			});
			//#2, with inc and mov instead of just inc for whatever reason
			pattern("66 FF ? 66 89 ? 86 00 00 00").for_each_result([framerate, propagatecounters, constants, pointers, param_floats] (auto found) // movzx X, word ptr [Y + 0x88] : X = general purpose 32 bit register, Y = general purpose 64 bit register
			mutable {
				auto inc_reg_byte = *found.get<uint8_t>(2);
				auto mov_reg_byte = *found.get<uint8_t>(5);
				if ((inc_reg_byte & 0xF8) == 0xC0) //make sure it's an inc and not a dec
				{
					if ((mov_reg_byte & 0xC0) == 0x80) //make sure it's a valid mov
					{
						auto value_reg = inc_reg_byte & 0x7;
						if (value_reg == ((mov_reg_byte >> 3) & 0x7)) //makes sure it's referring to the same register
						{
							size_t size;
							std::byte* space;
							pointers[0] = reinterpret_cast<uintptr_t>(propagatecounters);
							if (!ParametricASMJump("cmp byte ptr [rip + ?0], 1; jne A; inc ax; A: mov [rdi + 0x86], ax;", &space, &size, constants, pointers, param_floats))
							{
								Patch<uint8_t>(space + 11, inc_reg_byte);
								Patch<uint8_t>(space + 14, mov_reg_byte);
								WriteOffsetValue(space + size - 4, found.get<void>(0xA)); //Fill the final jump with the correct address
								InjectHook(found.get<void>(), space, PATCH_JUMP);
							}
						}
					}
				}
			});

			//HP regen speed
			match = pattern("07 03 F0 EB 02 03 F3 8B C6 99 83 E2 7F 03 C2 C1").count(1);
			constants[0] = 128 * (framerate / 30.0f);
			if (!ParametricASMJump("mov r8d, $0; xor edx, edx; mov eax, esi; div r8d;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x12)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}
			match = pattern("B9 0F 27 00 00 F7 D9 41 8B D0 C1 E1 07 03 F1 8B").count(1);
			if (!ParametricASMJump("mov esi, edx; mov edx, r8d;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xF)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}

			/*Specific characters moveset fixes*/

			//Queen's Divine Judgement ability gauge's cost (per frame)
			match = pattern("D0 74 0F F7 DA 45 33 C0 48 8B CF E8 D0 60 00 00").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("xor r8d, r8d; cvtsi2ss xmm11, edx; mulss xmm11, %0; cvtss2si edx, xmm11; neg edx", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x3), space, PATCH_JUMP);
			}
			//Queen's Divine Judgement rotation speed
			match = pattern("F3 0F 10 05 2C 65 2D 00 F3 0F 58 87 B8 00 00 00").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("movss xmm10, %0; mulss xmm1, xmm10; mulss xmm0, xmm10; addss xmm0, dword ptr [rdi + 0xB8];", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x10)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x8), space, PATCH_JUMP);
			}

			//Nine's jump (and high jump) travel distance (take into account accumulating floating point errors when adjusting the values)
			match = pattern("87 FC 00 00 00 F3 0F 58 53 08 F3 0F 58 4B 04 F3 0F 58 03 F3 0F 11 03 F3").count(1);
			param_floats[0] = 20.0f / (framerate - 10.0f);
			if (!ParametricASMJump("movss xmm10, %0; mulss xmm2, xmm10; mulss xmm1, xmm10; mulss xmm0, xmm10; addss xmm2, dword ptr [rbx + 8]; addss xmm1, dword ptr [rbx + 4]; addss xmm0, dword ptr [rbx]", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x13)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}
			match = pattern("10 03 F3 0F 58 87 FC 00 00 00 F3 0F 58 53 08 F3").count(1);
			param_floats[0] = 20.0f / (framerate - 10.0f);
			if (!ParametricASMJump("movss xmm0, dword ptr [rdi + 0xFC]; movss xmm10, %0; mulss xmm2, xmm10; mulss xmm1, xmm10; mulss xmm0, xmm10; addss xmm2, dword ptr [rbx + 8]; addss xmm1, dword ptr [rbx + 4]; addss xmm0, dword ptr [rbx]", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x14)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x2), space, PATCH_JUMP);
			}

			//Rocket Launcher guy projectile speed (instead of being set every time the function is called, it's only done once, so it needs to be reset for the next cycle)
			match = pattern("00 00 48 8B 8D 10 01 00 00 48 33 CC E8 4F 50 E8").count(1);
			param_floats[0] = framerate / 30.0f;
			if (!ParametricASMJump("mov rcx, qword ptr [rbp + 0x110]; movss xmm2, %0; movss xmm3, dword ptr [rdi + 0x54]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x54], xmm3; movss xmm3, dword ptr [rdi + 0x58]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x58], xmm3; movss xmm3, dword ptr [rdi + 0x5C]; mulss xmm3, xmm2; movss dword ptr [rdi + 0x5C], xmm3;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x9)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x2), space, PATCH_JUMP);
			}

			//Fire RF (and potentially similar attacks) bullet elapsed range [ref: 0x002A13A8]
			match = pattern("05 93 57 2C 00 F3 41 0F 10 84 06 B8 00 00 00 0F").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("movss xmm0, dword ptr [r14 + rax + 0xB8]; mulss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xF)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}
			//Fire RF (and potentially similar attacks) bullet speed
			match = pattern("0F 10 43 10 F3 0F 58 53 08 F3 0F 58 4B 04 F3 0F 58 03 F3 0F 11 03 F3 0F").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("movss xmm13, %0; mulss xmm2, xmm13; mulss xmm1, xmm13; mulss xmm0, xmm13; addss xmm2, dword ptr [rbx + 8]; addss xmm1, dword ptr [rbx + 4]; addss xmm0, dword ptr [rbx];", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x12)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}

			//Deuce flute energy sphere horizontal orbit
			match = pattern("F3 0F 58 05 A8 5B 2C 00 0F 2F C1 F3 0F 11 83 FC").count(1);
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x57FBE8;
			if (!ParametricASMJump("movss xmm4, %0; mulss xmm4, dword ptr [rip + ?0]; addss xmm0, xmm4", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(), space, PATCH_JUMP);
			}
			//Deuce flute energy sphere vertical orbit
			match = pattern("04 01 00 00 F3 0F 58 05 34 5B 2C 00 0F 2F C1 F3").count(1);
			param_floats[0] = 30.0f / framerate;
			pointers[0] = baseaddress + 0x57FBA8;
			if (!ParametricASMJump("movss xmm4, %0; mulss xmm4, dword ptr [rip + ?0]; addss xmm0, xmm4;", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}
			//Deuce flute energy sphere bouncing pattern
			auto increasestartvalue = pattern("01 00 00 76 0B 48 C7 83 00 01 00 00 00 00 20 41").count(1);
			Patch<float>(increasestartvalue.get_first<void>(0xC), (30.0f / framerate) * 10.0f);
			match = pattern("0F 10 83 00 01 00 00 F3 0F 5C 05 C5 5C 2C 00 F3").count(1);
			param_floats[0] = pow(30.0f / framerate, 2);
			if (!ParametricASMJump("subss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xF)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}
			//Deuce flute energy sphere when following targets (speed and amplitude)
			match = pattern("C8 80 E1 01 F3 44 0F 11 43 54 F3 44 0F 11 53 58").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("mulss xmm9, xmm7; mulss xmm9, xmm1; movss xmm4, %0; mulss xmm8, xmm4; mulss xmm9, xmm4; mulss xmm10, xmm4; movss dword ptr [rbx + 0x54], xmm8; movss dword ptr [rbx + 0x58], xmm10; movss dword ptr [rbx + 0x5C], xmm9", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x20)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}
			match = pattern("15 73 61 2C 00 48 8D 55 B8 48 8B CB 0F 28 DA E8").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("mulss xmm2, %0; lea rdx, [rbp - 0x48]; mov rcx, rbx", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}
			//Deuce flute energy sphere when going back to Deuce
			match = pattern("0F B6 0D C0 ED 39 00 F3 44 0F 11 43 54 F3 44 0F").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("lea rdx, [rbx + 0x44]; mov eax, 0x20; and cl, 1; movss xmm4, %0; mulss xmm8, xmm4; mulss xmm9, xmm4; mulss xmm10, xmm4; movss dword ptr [rbx + 0x54], xmm8; movss dword ptr [rbx + 0x58], xmm10; movss dword ptr [rbx + 0x5C], xmm9", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x25)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}

			//Enemy grenade (thrown by generals) bouncing pattern
			match = pattern("00 F3 41 0F 11 06 F3 41 0F 11 4E 04 89 8F 20 01").count(1);
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("mulss xmm1, %0; movss dword ptr [r14 + 0x4], xmm1", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x6), space, PATCH_JUMP);
			}
			match = pattern("F3 0F 5C 05 ? ? 2E 00 4C 8D 87 AC 00 00 00 48 8D").count(2); //case 3 and case 4
			param_floats[0] = pow(30.0f / framerate, 2) * 1.9f;
			if (!ParametricASMJump("subss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get(0).get<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get(0).get<void>(), space, PATCH_JUMP);
			}
			param_floats[0] = pow(30.0f / framerate, 2) * 1.9f;
			if (!ParametricASMJump("subss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get(1).get<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get(1).get<void>(), space, PATCH_JUMP);
			}
			auto maxallowedincrement = pattern("76 ? C7 87 00 01 00 00 00 00 F0 41 EB ? F3 41").count(2);
			Patch<float>(maxallowedincrement.get(0).get<void>(0x8), (30.0f / framerate) * 30.0f);
			Patch<float>(maxallowedincrement.get(1).get<void>(0x8), (30.0f / framerate) * 30.0f);
			match = pattern("00 0F 2F 05 ? ? 2E 00 F3 0F 11 87 00 01 00 00").count(2);
			param_floats[0] = (30.0f / framerate) * 30.0f;
			if (!ParametricASMJump("movss xmm6, %0; comiss xmm0, xmm6", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get(0).get<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get(0).get<void>(0x1), space, PATCH_JUMP);
			}
			param_floats[0] = (30.0f / framerate) * 30.0f;
			if (!ParametricASMJump("movss xmm6, %0; comiss xmm0, xmm6", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get(1).get<void>(0x8)); //Fill the final jump with the correct address
				InjectHook(match.get(1).get<void>(0x1), space, PATCH_JUMP);
			}
			//Enemy grenade range
			match = pattern("87 00 01 00 00 F3 41 0F 10 56 08 F3 41 0F 10 4E").count(1); //case 3
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("movss xmm2, dword ptr [r14 + 0x8]; movss xmm1, dword ptr [r14 + 0x4]; movss xmm0, dword ptr [r14]; movss xmm4, %0; mulss xmm2, xmm4; mulss xmm0, xmm4; addss xmm2, dword ptr [rdx + 0x8]; addss xmm1, dword ptr [rdx + 0x4]; addss xmm0, dword ptr [rdx]", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x24)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x5), space, PATCH_JUMP);
			}
			match = pattern("00 F3 41 0F 10 54 24 08 F3 41 0F 10 4C 24 04 49").count(1); //case 4
			param_floats[0] = 30.0f / framerate;
			if (!ParametricASMJump("movss xmm2, dword ptr [r12 + 0x8]; movss xmm1, dword ptr [r12 + 0x4]; movss xmm0, dword ptr [r12]; movss xmm4, %0; mulss xmm2, xmm4; mulss xmm0, xmm4; addss xmm2, dword ptr [r15 + 0x8]; addss xmm1, dword ptr [r15 + 0x4]; addss xmm0, dword ptr [r15]; mov rdx, r15", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0x29)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x1), space, PATCH_JUMP);
			}

			//RTS turret animation timings
			match = pattern("7E 06 41 83 EE 02 EB 06 41 BE").count(1); //Delay before rising
			if (!ParametricASMJump("cmp word ptr [rdi + 0x1B0], 0; jle A; dec word ptr [rdi + 0x1B0]; jmp B; A: sub r14d, 2; B: nop", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xE)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x2), space, PATCH_JUMP);
			}
			match = pattern("00 0F 5B C0 F3 0F 59 05 B8 84 12 00 F3 0F 5E C7").count(1); //Adjust tilt when rising
			param_floats[0] = 3.14159f * (30.0f / framerate);
			if (!ParametricASMJump("mulss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x4), space, PATCH_JUMP);
			}
			match = pattern("0F 5B C0 F3 0F 59 05 E9 87 12 00 F3 0F 5E 05 49").count(1); //Adjust tilt when falling (and set the delay)
			constants[0] = 45 * (framerate / 30.0f - 1);
			param_floats[0] = 3.14159f * (30.0f / framerate);
			if (!ParametricASMJump("mov word ptr [rsi + 0x1B0], $0; mulss xmm0, %0", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xB)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x3), space, PATCH_JUMP);
			}

		}

		const float fovoverride = GetPrivateProfileIntW(L"FOV", L"FOVPercentage", 0, wcModulePath) / 100.0f;
		if (fovoverride > 0.0f)
		{
			auto keepcutscenefov = trampoline->Pointer<int8_t>();
			*keepcutscenefov = GetPrivateProfileIntW(L"FOV", L"KeepCutsceneFOV", 1, wcModulePath);

			match = pattern("0F 59 35 45 41 1D 00 44 0F 29 50 A8 44 0F 29 58").count(1);
			param_floats[0] = fovoverride;
			pointers[0] = reinterpret_cast<uintptr_t>(keepcutscenefov);
			pointers[1] = baseaddress + 0x658F70;
			if (!ParametricASMJump("movaps xmmword ptr [rax - 0x58], xmm10; cmp byte ptr [rip + ?0], 1; jnz A; cmp dword ptr [rip + ?1], 1; jz B; A: mulss xmm6, %0; B: nop", &space, &size, constants, pointers, param_floats))
			{
				WriteOffsetValue(space + size - 4, match.get_first<void>(0xC)); //Fill the final jump with the correct address
				InjectHook(match.get_first<void>(0x7), space, PATCH_JUMP);
			}
		}

	}
	else {
		MessageBox(
			NULL,
			(LPCWSTR)L"Couldn't locate the required functions in keystone.dll for the patch.\nMake sure you are using the included keystone.dll in this folder from the github release.",
			(LPCWSTR)L"keystone.dll Error",
			MB_ICONWARNING | MB_OK
		);
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
