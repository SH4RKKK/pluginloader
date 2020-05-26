#include <ntdll.h>
#include <delayimp.h>
#include <pe/module.h>
#include <pe/export_directory.h>
#include <xorstr.hpp>

#include <filesystem>
namespace fs = std::filesystem;
#include <unordered_map>

typedef void(__cdecl* PFN_PLUGIN_INIT)(void);
struct PLUGIN_INFO {
  const wchar_t* pwzName;
  const wchar_t* pwzVersion;
  const wchar_t* pwzDescription;
  PFN_PLUGIN_INIT pfnInit;
};
typedef bool(__cdecl* PFN_GETPLUGININFO)(PLUGIN_INFO*);

std::unordered_map<std::wstring, PLUGIN_INFO> _plugins;

VOID NTAPI ApcLoadPlugins(ULONG_PTR Parameter) {
  WIN32_FIND_DATAW findFileData;
  const auto fileName = fs::current_path().append(xorstr_("plugins\\*.dll"));
  auto hFindFile = FindFirstFileW(fileName.c_str(), &findFileData);
  if (hFindFile) {
    do {
      PLUGIN_INFO pluginInfo;
      memset(&pluginInfo, 0, sizeof pluginInfo);

      auto hModule = LoadLibraryExW(findFileData.cFileName, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
      if (!hModule)
        continue;
      auto pfnGetPluginInfo = (PFN_GETPLUGININFO)GetProcAddress(hModule, xorstr_("GetPluginInfo"));
      if (!pfnGetPluginInfo || !pfnGetPluginInfo(&pluginInfo)) {
        FreeLibrary(hModule);
        continue;
      }
      if (pluginInfo.pfnInit)
        pluginInfo.pfnInit();
      _plugins[findFileData.cFileName] = pluginInfo;
    } while (FindNextFileW(hFindFile, &findFileData));
    FindClose(hFindFile);
  }
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hInstance);
    QueueUserAPC(&ApcLoadPlugins, NtCurrentThread(), 0);
  }
  return TRUE;
}

ExternC const PfnDliHook __pfnDliNotifyHook2 = [](unsigned dliNotify, PDelayLoadInfo pdli) -> FARPROC
{
  pe::module* module;
  wchar_t path[_MAX_PATH];
  UINT count;

  switch (dliNotify) {
    case dliNotePreLoadLibrary:
      NtTestAlert();
      module = pe::instance_module();
      if (!_stricmp(pdli->szDll, module->export_directory()->name())) {
        count = GetSystemDirectoryW(path, _countof(path));
        if (count && swprintf_s(path + count, _countof(path) - count, xorstr_(L"\\%hs"), pdli->szDll) > 0)
          return (FARPROC)LoadLibraryExW(path, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
      }
      break;
  }
  return nullptr;
};
