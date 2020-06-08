#include <phnt_windows.h>
#include <phnt.h>
#include <delayimp.h>

#include <filesystem>
#include <unordered_map>

#include <pe/export_directory.h>
#include <pe/module.h>
#include <wil/stl.h>
#include <wil/win32_helpers.h>
#include <xorstr.hpp>


struct PLUGIN_INFO
{
  const wchar_t *pwzName;
  const wchar_t *pwzVersion;
  const wchar_t *pwzDescription;
  void(__cdecl *pfnInit)(void);
};
typedef void(__cdecl *PFN_GETPLUGININFO)(PLUGIN_INFO *);

VOID NTAPI ApcLoadPlugins(ULONG_PTR Parameter)
{
  auto find_file_data = WIN32_FIND_DATAW();
  const auto folder = std::filesystem::path(pe::get_module()->full_name()).remove_filename().append(xorstr_(L"plugins"));
  const auto filter = folder / xorstr_(L"*.dll");
  auto find_file_handle = FindFirstFileW(filter.c_str(), &find_file_data);
  if ( find_file_handle != INVALID_HANDLE_VALUE ) {
    do {
      const auto path = folder / find_file_data.cFileName;
      auto hModule = static_cast<pe::module *>(LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH));
      if ( !hModule )
        continue;
      auto GetPluginInfo = (PFN_GETPLUGININFO)GetProcAddress(hModule, xorstr_("GetPluginInfo"));
      if ( !GetPluginInfo ) {
        FreeLibrary(hModule);
        continue;
      }

      auto info = PLUGIN_INFO();
      memset(&info, 0, sizeof info);
      GetPluginInfo(&info);

      if ( info.pfnInit )
        info.pfnInit();

      hModule->hide_from_module_lists();
    } while ( FindNextFileW(find_file_handle, &find_file_data) );
    FindClose(find_file_handle);
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

ExternC const PfnDliHook __pfnDliNotifyHook2 = [](unsigned dliNotify, PDelayLoadInfo pdli) -> FARPROC {
  if ( dliNotify == dliNotePreLoadLibrary ) {
    const auto module = pe::instance_module();
    if ( !_stricmp(pdli->szDll, module->export_directory()->name()) ) {
      NtTestAlert();
      if ( std::wstring result; SUCCEEDED(wil::GetSystemDirectoryW(result)) ) {
        const auto path = std::filesystem::path(result).append(pdli->szDll);
        return (FARPROC)LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
      }
    }
  }
  return nullptr;
};
