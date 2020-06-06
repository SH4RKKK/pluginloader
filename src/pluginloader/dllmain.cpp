#include <ntdll.h>
#include <delayimp.h>
#include <pe/module.h>
#include <pe/export_directory.h>
#include <wil/stl.h>
#include <wil/win32_helpers.h>
#include <xorstr.hpp>

#include <filesystem>
namespace fs = std::filesystem;
#include <unordered_map>

struct PLUGIN_INFO {
  const wchar_t *pwzName;
  const wchar_t *pwzVersion;
  const wchar_t *pwzDescription;
  void(__cdecl *pfnInit)(void);
};
typedef void(__cdecl *PFN_GETPLUGININFO)(PLUGIN_INFO *);

std::unordered_map<std::wstring, PLUGIN_INFO> _plugins;

VOID NTAPI ApcLoadPlugins(ULONG_PTR Parameter) {
  WIN32_FIND_DATAW findFileData;
  const auto folder = fs::path(pe::get_module()->full_name()).remove_filename().append(xorstr_(L"plugins"));
  const auto filter = folder / xorstr_(L"*.dll");
  auto hFindFile = FindFirstFileW(filter.c_str(), &findFileData);
  if ( hFindFile != INVALID_HANDLE_VALUE ) {
    do {
      PLUGIN_INFO pluginInfo;
      memset(&pluginInfo, 0, sizeof pluginInfo);

      const auto path = folder / findFileData.cFileName;
      auto hModule = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
      if ( !hModule )
        continue;
      auto pfnGetPluginInfo = (PFN_GETPLUGININFO)GetProcAddress(hModule, xorstr_("GetPluginInfo"));
      if ( !pfnGetPluginInfo ) {
        FreeLibrary(hModule);
        continue;
      }
      pfnGetPluginInfo(&pluginInfo);
      if ( pluginInfo.pfnInit )
        pluginInfo.pfnInit();
      _plugins[findFileData.cFileName] = pluginInfo;
    } while ( FindNextFileW(hFindFile, &findFileData) );
    FindClose(hFindFile);
  }
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
  if ( fdwReason == DLL_PROCESS_ATTACH ) {
    DisableThreadLibraryCalls(hInstance);
    QueueUserAPC(&ApcLoadPlugins, NtCurrentThread(), 0);
  }
  return TRUE;
}

ExternC const PfnDliHook __pfnDliNotifyHook2 = [](unsigned dliNotify, PDelayLoadInfo pdli) -> FARPROC
{
  if ( dliNotify == dliNotePreLoadLibrary ) {
    const auto module = pe::instance_module();
    if ( !_stricmp(pdli->szDll, module->export_directory()->name()) ) {
      NtTestAlert();
      if ( std::wstring result; SUCCEEDED(wil::GetSystemDirectoryW(result)) ) {
        const auto path = fs::path(result).append(pdli->szDll);
        return (FARPROC)LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
      }
    }
  }
  return nullptr;
};
