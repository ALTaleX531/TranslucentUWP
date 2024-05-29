#include "pch.h"
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define HINST_THISCOMPONENT ((HINSTANCE)&__ImageBase)

using namespace std::chrono;
using namespace winrt;
using namespace winrt::Windows::Foundation::Collections;
using namespace winrt::Windows::UI;
using namespace winrt::Windows::UI::ViewManagement;
using namespace winrt::Windows::UI::Xaml;
using namespace winrt::Windows::UI::Xaml::Controls;
using namespace winrt::Windows::ApplicationModel::Core;

const char* get_ini_file_path_ansi()
{
	static char ini_file_path[MAX_PATH + 1] = {};
	if (!strnlen_s(ini_file_path, MAX_PATH))
	{
		check_bool(GetModuleFileNameA(HINST_THISCOMPONENT, ini_file_path, MAX_PATH) != 0);
		PathRemoveFileSpecA(ini_file_path);
		PathAppendA(ini_file_path, "config.ini");
	}

	return ini_file_path;
}
const wchar_t* get_ini_file_path()
{
	static wchar_t ini_file_path[MAX_PATH + 1] = {};
	if (!wcsnlen_s(ini_file_path, MAX_PATH))
	{
		check_bool(GetModuleFileNameW(HINST_THISCOMPONENT, ini_file_path, MAX_PATH) != 0);
		PathRemoveFileSpecW(ini_file_path);
		PathAppendW(ini_file_path, L"config.ini");
	}

	return ini_file_path;
}

void enum_process(const std::vector<std::wstring_view>& process_list, std::function<void(DWORD)>&& callback)
{
	check_bool(callback != nullptr);
	HANDLE toolhelp_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	auto clean_up = std::scope_exit([&]
	{
		if (toolhelp_snapshot)
		{
			CloseHandle(toolhelp_snapshot);
		}
	});
	PROCESSENTRY32W pe = {sizeof(pe)};
	check_bool(Process32FirstW(toolhelp_snapshot, &pe));

	do
	{
		for (const auto& item : process_list)
		{
			if (!_wcsicmp(pe.szExeFile, item.data()))
			{
				callback(pe.th32ProcessID);
			}
		}
	}
	while (Process32NextW(toolhelp_snapshot, &pe));
}

HMODULE get_process_module(HANDLE process_handle, LPCSTR dll_path) try
{
	DWORD needed = 0;
	HMODULE module_handle = nullptr;

	check_bool(EnumProcessModules(process_handle, nullptr, 0, &needed));

	DWORD module_count = needed / sizeof(HMODULE);
	auto module_list = std::make_unique<HMODULE[]>(module_count);

	check_bool(EnumProcessModules(process_handle, module_list.get(), needed, &needed));

	for (DWORD i = 0; i < module_count; i++)
	{
		HMODULE module_item = module_list[i];

		if (module_item)
		{
			CHAR module_name[MAX_PATH + 1];
			GetModuleFileNameExA(process_handle, module_item, module_name, MAX_PATH);

			if (!_stricmp(module_name, dll_path))
			{
				module_handle = module_item;
				break;
			}
		}
	}

	return module_handle;
}
catch(...)
{
	return nullptr;
}

void suspend_or_resume_other_threads(bool suspend)
{
	HANDLE toolhelp_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	auto clean_up = std::scope_exit([&]
	{
		if (toolhelp_snapshot)
		{
			CloseHandle(toolhelp_snapshot);
		}
	});

	THREADENTRY32 te{ sizeof(THREADENTRY32) };

	check_bool(Thread32First(toolhelp_snapshot, &te));
	do
	{
		if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != GetCurrentThreadId())
		{
			HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
			auto clean_up = std::scope_exit([&]
			{
				if (thread_handle)
				{
					CloseHandle(thread_handle);
				}
			});

			if (suspend)
			{
				SuspendThread(thread_handle);
			}
			else
			{
				ResumeThread(thread_handle);
			}
		}
	}
	while (Thread32Next(toolhelp_snapshot, &te));
}

void inject_callback_to_thread(DWORD thread_id, std::function<void()> callback)
{
	HANDLE thread_handle = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
	auto clean_up = std::scope_exit([&]
	{
		if (thread_handle)
		{
			CloseHandle(thread_handle);
		}
	});

	BYTE shell_code[] =
	{
		// sub rsp, 28h
		0x48, 0x83, 0xec, 0x28,
		// mov [rsp + 18], rax
		0x48, 0x89, 0x44, 0x24, 0x18,
		// mov [rsp + 10h], rcx
		0x48, 0x89, 0x4c, 0x24, 0x10,
		// mov rcx, function_parameter
		0x48, 0xb9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		// mov rax, function_pointer
		0x48, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		// call rax
		0xff, 0xd0,
		// mov rcx, [rsp + 10h]
		0x48, 0x8b, 0x4c, 0x24, 0x10,
		// mov rax, [rsp + 18h]
		0x48, 0x8b, 0x44, 0x24, 0x18,
		// add rsp, 28h
		0x48, 0x83, 0xc4, 0x28,
		// mov r11, context.Rip
		0x49, 0xbb, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		// jmp r11
		0x41, 0xff, 0xe3
	};
	SuspendThread(thread_handle);

	CONTEXT context{};
	context.ContextFlags = CONTEXT_FULL;
	check_bool(GetThreadContext(thread_handle, &context));

	auto proxy_callback = [](ULONG_PTR parameter) -> void
	{
		auto callback_ptr = reinterpret_cast<std::function<void()>*>(parameter);
		auto callback = *callback_ptr;
		delete callback_ptr;

		OutputDebugStringW(L"proxy_callback\n");
		callback();
	};
	*reinterpret_cast<PVOID*>(&shell_code[16]) = static_cast<void*>(new std::function<void()> {callback});
	*reinterpret_cast<PVOID*>(&shell_code[26]) = static_cast<void*>(static_cast<void(WINAPI*)(ULONG_PTR)>(proxy_callback));
	*reinterpret_cast<ULONG_PTR*>(&shell_code[52]) = context.Rip;

	const auto page_size = 1 << 12;
	auto buffer = static_cast<char*>(
					  VirtualAlloc(
						  nullptr,
						  page_size,
						  MEM_COMMIT | MEM_RESERVE,
						  PAGE_EXECUTE_READWRITE
					  )
				  );
	memcpy_s(buffer, page_size, shell_code, sizeof(shell_code));
	context.Rip = reinterpret_cast<ULONG_PTR>(buffer);
	check_bool(SetThreadContext(thread_handle, &context));

	ResumeThread(thread_handle);
}

DWORD get_main_thread_id()
{
	HANDLE toolhelp_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	auto clean_up = std::scope_exit([&]
	{
		if (toolhelp_snapshot)
		{
			CloseHandle(toolhelp_snapshot);
		}
	});

	THREADENTRY32 te{ sizeof(THREADENTRY32) };

	check_bool(Thread32First(toolhelp_snapshot, &te));
	do
	{
		if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != GetCurrentThreadId())
		{
			return te.th32ThreadID;
		}
	}
	while (Thread32Next(toolhelp_snapshot, &te));

	return 0;
}

bool is_uwp()
{
	/*auto policy = AppPolicyWindowingModel::AppPolicyWindowingModel_None;
	AppPolicyGetWindowingModel(GetCurrentProcess(), &policy);

	return policy == AppPolicyWindowingModel::AppPolicyWindowingModel_Universal;*/
	/*auto policy = AppPolicyCreateFileAccess::AppPolicyCreateFileAccess_Full;
	AppPolicyGetCreateFileAccess(GetCurrentProcess(), &policy);

	return policy == AppPolicyCreateFileAccess::AppPolicyCreateFileAccess_Limited;*/
	return !GetModuleHandle(L"Microsoft.WinUI.dll");
}

bool is_app_using_winui3()
{
	return GetModuleHandle(L"Microsoft.Internal.FrameworkUdk.dll");
}

auto make_acrylic_brush(ElementTheme theme)
{
	static constexpr auto sc_darkThemeColor = Color{ 255, 32, 32, 32 };
	static constexpr auto sc_lightThemeColor = Color{ 255, 243, 243, 243 };

	static constexpr auto sc_lightTintColorOpacity = 0.15f;
	static constexpr auto sc_darkTintColorOpacity = 0.3f;

	static constexpr auto sc_lightTintColorLuminosityOpacity = 0.8f;
	static constexpr auto sc_darkTintColorLuminosityOpacity = 0.8f;

	Color color = {};
	float tint_opacity = 0.f;
	float tint_luminosity_opacity = 0.f;

	if (theme == ElementTheme::Light)
	{
		color.A = GetPrivateProfileIntW(L"light", L"alpha", sc_lightThemeColor.A, get_ini_file_path());
		color.R = GetPrivateProfileIntW(L"light", L"red", sc_lightThemeColor.R, get_ini_file_path());
		color.G = GetPrivateProfileIntW(L"light", L"green", sc_lightThemeColor.G, get_ini_file_path());
		color.B = GetPrivateProfileIntW(L"light", L"blue", sc_lightThemeColor.B, get_ini_file_path());
		tint_opacity = static_cast<float>(GetPrivateProfileIntW(L"light", L"tint_opacity", static_cast<INT>(sc_lightTintColorOpacity * 100.f), get_ini_file_path())) / 100.f;
		tint_luminosity_opacity = static_cast<float>(GetPrivateProfileIntW(L"light", L"tint_luminosity_opacity", static_cast<INT>(sc_lightTintColorLuminosityOpacity * 100.f), get_ini_file_path())) / 100.f;
	}
	else
	{
		color.A = GetPrivateProfileIntW(L"dark", L"alpha", sc_darkThemeColor.A, get_ini_file_path());
		color.R = GetPrivateProfileIntW(L"dark", L"red", sc_darkThemeColor.R, get_ini_file_path());
		color.G = GetPrivateProfileIntW(L"dark", L"green", sc_darkThemeColor.G, get_ini_file_path());
		color.B = GetPrivateProfileIntW(L"dark", L"blue", sc_darkThemeColor.B, get_ini_file_path());
		tint_opacity = static_cast<float>(GetPrivateProfileIntW(L"dark", L"tint_opacity", static_cast<INT>(sc_darkTintColorOpacity * 100.f), get_ini_file_path())) / 100.f;
		tint_luminosity_opacity = static_cast<float>(GetPrivateProfileIntW(L"dark", L"tint_luminosity_opacity", static_cast<INT>(sc_darkTintColorLuminosityOpacity * 100.f), get_ini_file_path())) / 100.f;
	}

	auto brush = Media::AcrylicBrush();
	brush.BackgroundSource(Media::AcrylicBackgroundSource::HostBackdrop);
	brush.TintOpacity(tint_opacity);
	brush.TintLuminosityOpacity(tint_luminosity_opacity);
	brush.TintColor(color);
	brush.FallbackColor(color);
	brush.AlwaysUseFallback(false);

	return brush;
}

auto& get_acrylic_controller()
{
	static Microsoft::UI::Composition::SystemBackdrops::DesktopAcrylicController acrylic_controller{};
	return acrylic_controller;
}

bool winui_walk_visual_tree(Microsoft::UI::Xaml::DependencyObject element, std::function<bool(Microsoft::UI::Xaml::FrameworkElement element)> callback) try
{
	using VisualTreeHelper = Microsoft::UI::Xaml::Media::VisualTreeHelper;

	auto control = element.try_as<Control>();

	if (element)
	{
		if (control)
		{
			auto name = control.Name();
			OutputDebugStringW(
				std::format(
					L"class: {}, name: {}",
					get_class_name(element).c_str(),
					name.c_str()
				).c_str()
			);
		}
		else
		{
			OutputDebugStringW(
				std::format(
					L"class: {}, name: (unknown)",
					get_class_name(element).c_str()
				).c_str()
			);
		}
	}

	if (!callback)
	{
		return false;
	}
	if (!callback(element.try_as<Microsoft::UI::Xaml::FrameworkElement>()))
	{
		return false;
	}

	for (int32_t index = 0, child_count = VisualTreeHelper::GetChildrenCount(element); index < child_count; index++)
	{
		auto child = VisualTreeHelper::GetChild(element, index).try_as<Microsoft::UI::Xaml::UIElement>();

		if (!winui_walk_visual_tree(child, callback))
		{
			return false;
		}
	}

	return true;
}

catch (...)
{
	OutputDebugStringW(L"winui_walk_visual_tree caught an exception!\n");
	OutputDebugStringW(to_message().c_str());
	return false;
}

bool walk_visual_tree(DependencyObject element, std::function<bool(FrameworkElement element)> callback) try
{
	using VisualTreeHelper = Media::VisualTreeHelper;

	auto control = element.try_as<Control>();

	if (element)
	{
		if (control)
		{
			auto name = control.Name();
			OutputDebugStringW(
				std::format(
					L"class: {}, name: {}",
					get_class_name(element).c_str(),
					name.c_str()
				).c_str()
			);
		}
		else
		{
			OutputDebugStringW(
				std::format(
					L"class: {}, name: (unknown)",
					get_class_name(element).c_str()
				).c_str()
			);
		}
	}

	if (!callback)
	{
		return false;
	}
	if (!callback(element.try_as<FrameworkElement>()))
	{
		return false;
	}

	for (int32_t index = 0, child_count = VisualTreeHelper::GetChildrenCount(element); index < child_count; index++)
	{
		auto child = VisualTreeHelper::GetChild(element, index);

		if (!walk_visual_tree(child, callback))
		{
			return false;
		}
	}

	return true;
}
catch(...)
{
	OutputDebugStringW(L"walk_visual_tree caught an exception!\n");
	OutputDebugStringW(to_message().c_str());
	return false;
}

enum class mica_removal_status
{
	failed,
	succeeded,
	ok
};
mica_removal_status try_remove_mica(UIElement element) try
{
	MIDL_INTERFACE("707f26f5-042d-5ba6-a1c8-cbc66246f7a1")
IBackdropMaterialStatic :
	public IInspectable
	{
public:
		virtual HRESULT STDMETHODCALLTYPE get_ApplyToRootOrPageBackgroundProperty(ABI::Windows::UI::Xaml::IDependencyProperty * *dependencyProperty) = 0;
		virtual HRESULT STDMETHODCALLTYPE SetApplyToRootOrPageBackground(ABI::Windows::UI::Xaml::Controls::IControl * control, ::IInspectable * value) = 0;
		virtual HRESULT STDMETHODCALLTYPE GetApplyToRootOrPageBackground(ABI::Windows::UI::Xaml::Controls::IControl * control, ::IInspectable * *value) = 0;
	};

	auto backdrop_material_class = hstring(L"Microsoft.UI.Xaml.Controls.BackdropMaterial");
	com_ptr<IBackdropMaterialStatic> backdrop_material{ get_activation_factory<IBackdropMaterialStatic>(backdrop_material_class) };

	com_ptr<ABI::Windows::UI::Xaml::IDependencyProperty> backdrop_property = nullptr;
	check_hresult(
		backdrop_material->get_ApplyToRootOrPageBackgroundProperty(
			backdrop_property.put()
		)
	);

	auto dependency_property = backdrop_property.try_as<DependencyProperty>();
	auto value = element.ReadLocalValue(dependency_property);
	if (value == DependencyProperty::UnsetValue())
	{
		return mica_removal_status::failed;
	}

	if (unbox_value<bool>(value) == true)
	{
		element.RegisterPropertyChangedCallback(dependency_property, [dependency_property](winrt::Windows::UI::Xaml::DependencyObject const & sender, winrt::Windows::UI::Xaml::DependencyProperty const & dp)
		{
			if (dp == dependency_property)
			{
				sender.SetValue(dependency_property, box_value(false));
			}
		});
		element.SetValue(dependency_property, box_value(false));

		return mica_removal_status::succeeded;
	}

	return mica_removal_status::ok;
}
catch(...)
{
	return mica_removal_status::failed;
}

template <typename T>
bool try_appply_acrylic(UIElement element)
{
	auto control = element.try_as<T>();
	if (control)
	{
		/*MIDL_INTERFACE("06636C29-5A17-458D-8EA2-2422D997A922")
		IWindowPrivate : public IInspectable
		{
		public:
			virtual HRESULT get_TransparentBackground(boolean * value) = 0;
			virtual HRESULT put_TransparentBackground(boolean value) = 0;
		};

		Window::Current().as<IWindowPrivate>()->put_TransparentBackground(true);*/

		control.Background(make_acrylic_brush(control.ActualTheme()));
		control.ActualThemeChanged([control](FrameworkElement const & sender, winrt::Windows::Foundation::IInspectable const & theme)
		{
			control.Background(make_acrylic_brush(control.ActualTheme()));
		});
		return true;
	}

	return false;
}

bool try_transform_mica_to_acrylic(UIElement element)
{
	auto result = try_remove_mica(element);
	if (result == mica_removal_status::succeeded)
	{
		OutputDebugStringW(L"try_remove_mica ok!\n");

		OutputDebugStringW(L"try_appply_acrylic<Control>\n");
		if (!try_appply_acrylic<Control>(element))
		{
			OutputDebugStringW(L"try_appply_acrylic<Panel>\n");
			if (!try_appply_acrylic<Panel>(element))
			{
				OutputDebugStringW(L"try_appply_acrylic<Border>\n");
				try_appply_acrylic<Border>(element);
			}
		}
	}

	return result != mica_removal_status::failed;
}

bool transform_window_mica() try
{
	bool result = false;
	using VisualTreeHelper = Media::VisualTreeHelper;
	OutputDebugStringW(L"transform_window_mica\n");

	OutputDebugStringW(L"try Window::Current\n");
	auto window = Window::Current();
	if (!window)
	{
		return result;
	}

	OutputDebugStringW(L"try window.Content\n");
	auto content = window.Content();
	if (!content)
	{
		return result;
	}

	OutputDebugStringW(L"try walk_visual_tree\n");
	walk_visual_tree(content, [&](UIElement element)
	{
		if (!element)
		{
			return true;
		}
		result = try_transform_mica_to_acrylic(element);
		return !result;
	});
	/*walk_visual_tree(content, [&](UIElement element)
	{
		OutputDebugStringW(L"try_appply_acrylic<Control>\n");
		if (!try_appply_acrylic<Control>(element))
		{
			OutputDebugStringW(L"try_appply_acrylic<Panel>\n");
			if (!try_appply_acrylic<Panel>(element))
			{
				OutputDebugStringW(L"try_appply_acrylic<Border>\n");
				if (!try_appply_acrylic<Border>(element))
				{
					return true;
				}
			}
		}

		return false;
	});*/

	if (result)
	{
		window.Activate();
		OutputDebugStringW(L"transform_window_mica ok!\n");
	}
	else
	{
		OutputDebugStringW(L"transform_window_mica failed!\n");
	}
	return result;
}
catch (...)
{
	return false;
}

HRESULT STDMETHODCALLTYPE my_IFrameworkView_Run(ABI::Windows::ApplicationModel::Core::IFrameworkView* This);
decltype(&my_IFrameworkView_Run) g_pfn_IFrameworkView_Run = nullptr;
HRESULT STDMETHODCALLTYPE my_IFrameworkView_Run(ABI::Windows::ApplicationModel::Core::IFrameworkView* This)
{
	OutputDebugStringW(L"my_IFrameworkView_Run");

	if (!transform_window_mica())
	{
		auto timer = DispatcherTimer();
		timer.Interval(20ms);
		timer.Tick([timer](winrt::Windows::Foundation::IInspectable sender, winrt::Windows::Foundation::IInspectable event)
		{
			OutputDebugStringW(L"=================DispatcherTimer begin=================");
			if (transform_window_mica())
			{
				timer.Stop();
			}
			OutputDebugStringW(L"=================DispatcherTimer end=================");
		});
		timer.Start();
	}

	return g_pfn_IFrameworkView_Run(This);
}

namespace UWP
{
	MIDL_INTERFACE("f96d6d82-6e05-4c67-bc47-7cd8f7b40297")
IXamlTestHooks :
	public IUnknown
	{
public:
		virtual HRESULT STDMETHODCALLTYPE SetErrorHandlerCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetLoggerCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateDeviceLost() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetDeviceAndVisuals() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetDeviceAndVisualsAndDManip() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateDeviceLostOnOffThreadImageUpload() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateDeviceLostOnMetadataParse() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateSwallowedDeviceLostOnStartup() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetDCompDeviceLeakDetectionEnabled() = 0;
		virtual HRESULT STDMETHODCALLTYPE InitializeMouseMode() = 0;
		virtual HRESULT STDMETHODCALLTYPE UpdateMouseMode() = 0;
		virtual HRESULT STDMETHODCALLTYPE SuspendMouseMode() = 0;
		virtual HRESULT STDMETHODCALLTYPE RestoreMouseMode() = 0;
		virtual HRESULT STDMETHODCALLTYPE UpdateMouseModeArea() = 0;
		virtual HRESULT STDMETHODCALLTYPE PutApplicationMouseModeEnabled() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetApplicationMouseModeEnabled() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsDragDropInProgress() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetDCompDevice() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetWindowSizeOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetZoomScale() = 0;
		virtual HRESULT STDMETHODCALLTYPE OverrideTrimImageResourceDelay() = 0;
		virtual HRESULT STDMETHODCALLTYPE CleanupReleaseQueue() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetFinalReleaseQueue() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsRuntimeEnabledFeatureEnabled() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetRuntimeEnabledFeatureOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearAllRuntimeFeatureOverrides() = 0;
		virtual HRESULT STDMETHODCALLTYPE EmitHeapHandleExportEtwEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetPostTickCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetDependencyObjectPropertyValues() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetStoryboardStartedCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE InvokeInternalCommand() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetApplicationRequestedTheme() = 0;
		virtual HRESULT STDMETHODCALLTYPE UnsetApplicationRequestedTheme() = 0;
		virtual HRESULT STDMETHODCALLTYPE OverrideSystemTheme() = 0;
		virtual HRESULT STDMETHODCALLTYPE OverrideHighContrast() = 0;
		virtual HRESULT STDMETHODCALLTYPE OverrideAccentColor() = 0;
		virtual HRESULT STDMETHODCALLTYPE RemoveAccentColorOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetSystemFontCollectionOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE ShouldUseTypographicFontModel() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetGripperData() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetMetadata() = 0;
		virtual HRESULT STDMETHODCALLTYPE CreateLoopingSelector() = 0;
		virtual HRESULT STDMETHODCALLTYPE InjectBackButtonPress() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsWindowActivated() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetAtlasSizeHint() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetSeeitSayitPatternID() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateComponentHosted() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateXamlPresenterBehavior() = 0;
		virtual HRESULT STDMETHODCALLTYPE ShrinkApplicationViewVisibleBounds() = 0;
		virtual HRESULT STDMETHODCALLTYPE RequestReplayPreviousPointerUpdate_TempTestHook() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateSuspendToPauseAnimations() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateResumeToResumeAnimations() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetIsSuspended() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetIsRenderEnabled() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetTimeManagerClockOverrideConstant() = 0;
		virtual HRESULT STDMETHODCALLTYPE FireDCompAnimationCompleted() = 0;
		virtual HRESULT STDMETHODCALLTYPE CleanUpAfterTest() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetCompleteTimelinesAutomatically() = 0;
		virtual HRESULT STDMETHODCALLTYPE ForceDisconnectRootOnSuspend() = 0;
		virtual HRESULT STDMETHODCALLTYPE TriggerSuspend() = 0;
		virtual HRESULT STDMETHODCALLTYPE TriggerResume() = 0;
		virtual HRESULT STDMETHODCALLTYPE TriggerLowMemory() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetPrimaryPointerLastPositionOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearPrimaryPointerLastPositionOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE TestGetGlobalBoundsForUIElement() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetVisibleContentBounds() = 0;
		virtual HRESULT STDMETHODCALLTYPE CalculateAvailableMonitorRect() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateThemeChanged() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetLastInputMethod() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetLastInputMethod() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearDefaultLanguageString() = 0;
		virtual HRESULT STDMETHODCALLTYPE WaitForCommitCompletion() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetVisualTree() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsWindowFocused() = 0;
		virtual HRESULT STDMETHODCALLTYPE ShutdownXaml() = 0;
		virtual HRESULT STDMETHODCALLTYPE EnsureSatelliteDLLCustomDPCleanup() = 0;
		virtual HRESULT STDMETHODCALLTYPE InitializeXaml() = 0;
		virtual HRESULT STDMETHODCALLTYPE InjectWindowMessage() = 0;
		virtual HRESULT STDMETHODCALLTYPE UpdateFontScale() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetVisibleBounds() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearDesignModeSettings() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetForceIsFullScreen() = 0;
		virtual HRESULT STDMETHODCALLTYPE CancelAllConnectedAnimationsAndResetDefaults() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetPopupOverlayElement() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetShouldCheckQuirkCache() = 0;
		virtual HRESULT STDMETHODCALLTYPE EnableKeyboardInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE DisableKeyboardInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE CanFireKeyboardInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE DeletePlatformFamilyCache() = 0;
		virtual HRESULT STDMETHODCALLTYPE DeleteResourceDictionaryCaches() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetLastLayoutExceptionElement() = 0;
		virtual HRESULT STDMETHODCALLTYPE PostTestCheckForLeaks() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetIsHolographic() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateInputPaneOccludedRect() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetMockUIAClientsListening() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearMockUIAClientsListening() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetLightsTargetingElement() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetElementsTargetedByLight() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetCountOfVisualsTargeted() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetRealCompositionSurface() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetGenericXamlFilePathForMUX() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetHdrOutputOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetWantsRenderingEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetWantsCompositionTargetRenderedEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetThreadingAssertOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetCanTickWithNoContent() = 0;
		virtual HRESULT STDMETHODCALLTYPE AddTestLTE() = 0;
		virtual HRESULT STDMETHODCALLTYPE RemoveTestLTE() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearTestLTEs() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetPlayingSoundNodeCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsTrackingEffectiveVisibility() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsKeepingVisible() = 0;
		virtual HRESULT STDMETHODCALLTYPE RequestKeepAlive() = 0;
		virtual HRESULT STDMETHODCALLTYPE ReleaseKeepAlive() = 0;
		virtual HRESULT STDMETHODCALLTYPE TestGetActualToolTip() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedTranslation() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedRotation() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedScale() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedTransformMatrix() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedRotationAxis() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedCenterPoint() = 0;
		virtual HRESULT STDMETHODCALLTYPE ScheduleWaitForAnimatedFacadePropertyChanges() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateRegionsForContentDialog() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetBrowserHostCursor() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsStoryboardActive() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetSuspendOffThreadDecoding() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetSuspendSurfaceUpdates() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetUIAWindow() = 0;
		virtual HRESULT STDMETHODCALLTYPE RestoreDefaultFlipViewScrollWheelDelay() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetFlipViewScrollWheelDelay() = 0;
		virtual HRESULT STDMETHODCALLTYPE ApplyElevationEffect() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetApplicationLanguageOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearApplicationLanguageOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetCaretBrowsingModeGlobal() = 0;
		virtual HRESULT STDMETHODCALLTYPE CloseAllPopupsForTreeReset() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAllXamlRoots(ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Xaml::XamlRoot*>** xamlRoots) = 0;
		virtual HRESULT STDMETHODCALLTYPE EnableShadowsForTests() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetSimulateShadowsDisabledByPolicy() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetForceFallbackToLocalLights() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetCoreWindowVisibilityOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetBrushForXamlRoot() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetBrushForXamlRoot() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetElementsRenderedCount() = 0;
	};

	MIDL_INTERFACE("3b1f9832-6a1c-4fb4-afe3-3bc92159acda")
IDxamlCoreTestHooks :
	public IInspectable
	{
	};

	MIDL_INTERFACE("91be536b-9599-428b-9a72-0618f28019e8")
IDxamlCoreTestHooksStatics :
	public IInspectable
	{
public:
		virtual HRESULT STDMETHODCALLTYPE GetForCurrentThread(
			IDxamlCoreTestHooks * *ppResult
		) = 0;
	};

	MIDL_INTERFACE("412b49d7-b8b7-416a-b49b-57f9edbef991")
IXamlIsland :
	public IInspectable
	{
		virtual HRESULT STDMETHODCALLTYPE get_AppContent(
			IInspectable * *app_content
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE get_Content(
			ABI::Windows::UI::Xaml::IUIElement** element
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE put_Content(
			ABI::Windows::UI::Xaml::IUIElement* element
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE get_FocusController(
			IInspectable** focus_controller
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE get_MaterialProperties(
			IInspectable** material_properties
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE put_MaterialProperties(
			IInspectable* material_properties
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE SetScreenOffsetOverride(
			ABI::Windows::Foundation::Point offset_on_screen
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE SetFocus() = 0;
	};

	MIDL_INTERFACE("3ead2336-b073-456f-bcaf-82587eb63487")
IXamlIslandStatics :
	public IInspectable
	{
		virtual HRESULT STDMETHODCALLTYPE GetIslandFromElement(
			ABI::Windows::UI::Xaml::IDependencyObject * pElement,
			IXamlIsland * *ppResult
		) = 0;
	};

	MIDL_INTERFACE("b3ab45d8-6a4e-4e76-a00d-32d4643a9f1a")
IFrameworkApplicationPrivate :
	public IInspectable
	{
public:
		virtual HRESULT STDMETHODCALLTYPE StartOnCurrentThread(ABI::Windows::UI::Xaml::IApplicationInitializationCallback * callback) = 0;
		virtual HRESULT STDMETHODCALLTYPE CreateIsland(IXamlIsland** island) = 0;
		virtual HRESULT STDMETHODCALLTYPE CreateIslandWithAppWindow(IInspectable * app_window, IXamlIsland** island) = 0;
		virtual HRESULT STDMETHODCALLTYPE CreateIslandWithContentBridge(
			IInspectable * owner,
			IInspectable * content_bridge,
			IXamlIsland** island
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE RemoveIsland(IXamlIsland * island) = 0;
		virtual HRESULT STDMETHODCALLTYPE SetSynchronizationWindow(HWND hwnd) = 0;
	};
}

namespace WinUI
{
	MIDL_INTERFACE("43d4bcbd-4f02-4651-9ecc-dcfec9f786a7")
IXamlTestHooks :
	public IUnknown
	{
public:
		virtual HRESULT STDMETHODCALLTYPE SetErrorHandlerCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetLoggerCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateDeviceLost() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateDeviceLostOnOffThreadImageUpload() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateSwallowedDeviceLostOnStartup() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateDeviceLostOnMetadataParse() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateDeviceLostOnCreatingSvgDecoder() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetDeviceAndVisuals() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetDeviceOnly() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetDeviceAndVisualsAndDManip() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetDCompDeviceLeakDetectionEnabled() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsDragDropInProgress() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetDCompDevice() = 0;
		virtual HRESULT STDMETHODCALLTYPE MarkDeviceInstanceLost() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetD3D11GraphicsDeviceAddress() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetWindowSizeOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetZoomScale() = 0;
		virtual HRESULT STDMETHODCALLTYPE OverrideTrimImageResourceDelay() = 0;
		virtual HRESULT STDMETHODCALLTYPE CleanupReleaseQueue() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetFinalReleaseQueue() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsRuntimeEnabledFeatureEnabled() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetRuntimeEnabledFeatureOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearAllRuntimeFeatureOverrides() = 0;
		virtual HRESULT STDMETHODCALLTYPE EmitHeapHandleExportEtwEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetPostTickCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetDependencyObjectPropertyValues() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetStoryboardStartedCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE InvokeInternalCommand() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetApplicationRequestedTheme() = 0;
		virtual HRESULT STDMETHODCALLTYPE UnsetApplicationRequestedTheme() = 0;
		virtual HRESULT STDMETHODCALLTYPE OverrideSystemTheme() = 0;
		virtual HRESULT STDMETHODCALLTYPE OverrideHighContrast() = 0;
		virtual HRESULT STDMETHODCALLTYPE OverrideAccentColor() = 0;
		virtual HRESULT STDMETHODCALLTYPE RemoveThemingOverrides() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetSystemFontCollectionOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetGripperData() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetMetadata() = 0;
		virtual HRESULT STDMETHODCALLTYPE CreateLoopingSelector() = 0;
		virtual HRESULT STDMETHODCALLTYPE InjectBackButtonPress() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsWindowActivated() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetAtlasSizeHint() = 0;
		virtual HRESULT STDMETHODCALLTYPE ShrinkApplicationViewVisibleBounds() = 0;
		virtual HRESULT STDMETHODCALLTYPE RequestReplayPreviousPointerUpdate_TempTestHook() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateSuspendToPauseAnimations() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateResumeToResumeAnimations() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetIsSuspended() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetIsRenderEnabled() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetTimeManagerClockOverrideConstant() = 0;
		virtual HRESULT STDMETHODCALLTYPE FireDCompAnimationCompleted() = 0;
		virtual HRESULT STDMETHODCALLTYPE CleanUpAfterTest() = 0;
		virtual HRESULT STDMETHODCALLTYPE ForceDisconnectRootOnSuspend() = 0;
		virtual HRESULT STDMETHODCALLTYPE TriggerSuspend() = 0;
		virtual HRESULT STDMETHODCALLTYPE TriggerResume() = 0;
		virtual HRESULT STDMETHODCALLTYPE TriggerLowMemory() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetPrimaryPointerLastPositionOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearPrimaryPointerLastPositionOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE TestGetGlobalBoundsForUIElement() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetVisibleContentBounds() = 0;
		virtual HRESULT STDMETHODCALLTYPE CalculateAvailableMonitorRect() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateThemeChanged() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetLastInputMethod() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetLastInputMethod() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearDefaultLanguageString() = 0;
		virtual HRESULT STDMETHODCALLTYPE WaitForCommitCompletion() = 0;
		virtual HRESULT STDMETHODCALLTYPE ResetVisualTree() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsWindowFocused() = 0;
		virtual HRESULT STDMETHODCALLTYPE ShutdownXaml() = 0;
		virtual HRESULT STDMETHODCALLTYPE EnsureSatelliteDLLCustomDPCleanup() = 0;
		virtual HRESULT STDMETHODCALLTYPE InitializeXaml() = 0;
		virtual HRESULT STDMETHODCALLTYPE InjectWindowMessage() = 0;
		virtual HRESULT STDMETHODCALLTYPE UpdateFontScale() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetVisibleBounds() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetForceIsFullScreen() = 0;
		virtual HRESULT STDMETHODCALLTYPE CancelAllConnectedAnimationsAndResetDefaults() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetPopupOverlayElement() = 0;
		virtual HRESULT STDMETHODCALLTYPE EnableKeyboardInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE DisableKeyboardInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE CanFireKeyboardInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE EnablePointerInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE DisablePointerInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE CanFirePointerInputEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE DeletePlatformFamilyCache() = 0;
		virtual HRESULT STDMETHODCALLTYPE DeleteResourceDictionaryCaches() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetLastLayoutExceptionElement() = 0;
		virtual HRESULT STDMETHODCALLTYPE PostTestCheckForLeaks() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetIsHolographic() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateInputPaneOccludedRect() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetMockUIAClientsListening() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearMockUIAClientsListening() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetLightsTargetingElement() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetElementsTargetedByLight() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetCountOfVisualsTargeted() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetRealCompositionSurface() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetGenericXamlFilePathForMUX() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetHdrOutputOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetWantsRenderingEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetWantsCompositionTargetRenderedEvent() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetThreadingAssertOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetCanTickWithNoContent() = 0;
		virtual HRESULT STDMETHODCALLTYPE AddTestLTE() = 0;
		virtual HRESULT STDMETHODCALLTYPE RemoveTestLTE() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearTestLTEs() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetPlayingSoundNodeCallback() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsTrackingEffectiveVisibility() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsKeepingVisible() = 0;
		virtual HRESULT STDMETHODCALLTYPE RequestKeepAlive() = 0;
		virtual HRESULT STDMETHODCALLTYPE ReleaseKeepAlive() = 0;
		virtual HRESULT STDMETHODCALLTYPE TestGetActualToolTip() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedTranslation() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedRotation() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedScale() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedTransformMatrix() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedRotationAxis() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAnimatedCenterPoint() = 0;
		virtual HRESULT STDMETHODCALLTYPE ScheduleWaitForAnimatedFacadePropertyChanges() = 0;
		virtual HRESULT STDMETHODCALLTYPE SimulateRegionsForContentDialog() = 0;
		virtual HRESULT STDMETHODCALLTYPE IsStoryboardActive() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetElementInputWindow() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetSuspendOffThreadDecoding() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetUIAWindow() = 0;
		virtual HRESULT STDMETHODCALLTYPE RestoreDefaultFlipViewScrollWheelDelay() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetFlipViewScrollWheelDelay() = 0;
		virtual HRESULT STDMETHODCALLTYPE ApplyElevationEffect() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetApplicationLanguageOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearApplicationLanguageOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetCaretBrowsingModeGlobal() = 0;
		virtual HRESULT STDMETHODCALLTYPE CloseAllPopupsForTreeReset() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAllXamlRoots(ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Xaml::XamlRoot*>** xamlRoots) = 0;
		virtual HRESULT STDMETHODCALLTYPE ForceShadowsPolicy() = 0;
		virtual HRESULT STDMETHODCALLTYPE ClearShadowPolicyOverrides() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetXamlVisibilityOverride() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetBrushForXamlRoot() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetBrushForXamlRoot() = 0;
		virtual HRESULT STDMETHODCALLTYPE StopAllInteractions() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetImageSourceMaxSize() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAllRootVisualsNoRef() = 0;
		virtual HRESULT STDMETHODCALLTYPE DetachMemoryManagerEvents() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetTransparentBackground() = 0;
		virtual HRESULT STDMETHODCALLTYPE SetForceDebugSettingsTracingEvents() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetIslandAndBridge() = 0;
		virtual HRESULT STDMETHODCALLTYPE ThrottleImageTaskDispatcher() = 0;
		virtual HRESULT STDMETHODCALLTYPE RequestExecuteImageTaskDispatcher() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetElementRenderedVisuals() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetErrorHandlingTestHooks() = 0;
		virtual HRESULT STDMETHODCALLTYPE GetAllContentIslands() = 0;
	};

	MIDL_INTERFACE("61615723-8486-4376-84d5-27d0ff539580")
IDxamlCoreTestHooks :
	public IInspectable
	{
	};

	MIDL_INTERFACE("84118843-ff81-55aa-9153-bca77f03a774")
IDxamlCoreTestHooksStatics :
	public IInspectable
	{
public:
		virtual HRESULT STDMETHODCALLTYPE GetForCurrentThread(
			IDxamlCoreTestHooks * *ppResult
		) = 0;
	};

	MIDL_INTERFACE("c223b4d3-2a18-5f61-bdb8-f90d7fee9a8f")
IXamlIsland :
	public IInspectable
	{
		virtual HRESULT STDMETHODCALLTYPE get_Content(
			ABI::Windows::UI::Xaml::IUIElement** element
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE put_Content(
			ABI::Windows::UI::Xaml::IUIElement* element
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE get_FocusController(
			IInspectable** focus_controller
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE SetScreenOffsetOverride(
			ABI::Windows::Foundation::Point offset_on_screen
		) = 0;
		virtual HRESULT STDMETHODCALLTYPE TrySetFocus() = 0;
	};

	MIDL_INTERFACE("b3d608be-c816-469b-b645-9679b55717c7")
IXamlIslandStatics :
	public IInspectable
	{
		virtual HRESULT STDMETHODCALLTYPE GetIslandFromElement(
			ABI::Windows::UI::Xaml::IDependencyObject * pElement,
			IXamlIsland * *ppResult
		) = 0;
	};

	MIDL_INTERFACE("0c858b8b-3e6d-55f5-a221-673af73c19b3")
IFrameworkApplicationPrivate :
	public IInspectable
	{
public:
		// ABI::Microsoft::UI::Xaml::Window
		virtual HRESULT get_Windows(ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Xaml::Window*>** ppValue) = 0;
		virtual HRESULT StartOnCurrentThread(ABI::Windows::UI::Xaml::IApplicationInitializationCallback * callback) = 0;
		virtual HRESULT CreateIsland(IXamlIsland** island) = 0;
		virtual HRESULT CreateIslandWithContentBridge(
			IInspectable * owner,
			IInspectable * content_bridge,
			IXamlIsland** island
		) = 0;
		virtual HRESULT RemoveIsland(IXamlIsland * island) = 0;
		virtual HRESULT SetSynchronizationWindow(HWND hwnd) = 0;
	};
}

void run_callback()
{
	if (is_uwp())
	{

		// hook xaml island
		{
			auto name = hstring(RuntimeClass_Windows_UI_Xaml_Application);
			com_ptr<ABI::Windows::UI::Xaml::IApplication> application{ nullptr };

			com_ptr<ABI::Windows::UI::Xaml::IApplicationStatics> application_statics{ nullptr };
			check_hresult(
				RoGetActivationFactory(*reinterpret_cast<HSTRING*>(&name), IID_PPV_ARGS(application_statics.put()))
			);
			HRESULT hr = application_statics->get_Current(application.put());

			if (SUCCEEDED(hr) && application)
			{
				auto framework_application = application.as<UWP::IFrameworkApplicationPrivate>();
			}
			/*else
			{
				com_ptr<ABI::Windows::UI::Xaml::IApplicationFactory> application_factory{nullptr};
				check_hresult(
					RoGetActivationFactory(*reinterpret_cast<HSTRING*>(&name), IID_PPV_ARGS(application_factory.put()))
				);
			}*/
		}

		if (!g_pfn_IFrameworkView_Run)
		{
			com_ptr<ABI::Windows::ApplicationModel::Core::IFrameworkView> framework_view = nullptr;
			auto name = hstring(RuntimeClass_Windows_UI_Xaml_FrameworkView);
			check_hresult(
				RoActivateInstance(*reinterpret_cast<HSTRING*>(&name), reinterpret_cast<IInspectable**>(framework_view.put()))
			);
			framework_view = framework_view.as<ABI::Windows::ApplicationModel::Core::IFrameworkView>();

			suspend_or_resume_other_threads(true);
			auto vtable = *reinterpret_cast<void**>(framework_view.get());
			g_pfn_IFrameworkView_Run = reinterpret_cast<decltype(g_pfn_IFrameworkView_Run)>(reinterpret_cast<void**>(vtable)[9]);
			auto vtable_func = &reinterpret_cast<void**>(vtable)[9];

			DWORD old_protect = 0;
			VirtualProtect(vtable_func, sizeof(PVOID), PAGE_READWRITE, &old_protect);
			*vtable_func = my_IFrameworkView_Run;
			VirtualProtect(vtable_func, sizeof(PVOID), old_protect, &old_protect);
			suspend_or_resume_other_threads(false);
		}


		try
		{
			OutputDebugStringW(L"[uwp] try CoreApplication::Views()\n");
			auto view_collection = CoreApplication::Views();

			for (auto view : view_collection)
			{
				try
				{
					OutputDebugStringW(L"[uwp] try => view.CoreWindow()");
					auto core_window = view.CoreWindow();
					if (!core_window) throw_hresult(E_POINTER);

					OutputDebugStringW(L"[uwp] try => view.Dispatcher()");
					auto dispatcher = core_window.Dispatcher();
					if (!dispatcher) throw_hresult(E_POINTER);

					dispatcher.RunAsync(Core::CoreDispatcherPriority::High, []()
					{
						try
						{
							auto name = hstring(L"Windows.UI.Xaml.DxamlCoreTestHooks");
							com_ptr<UWP::IDxamlCoreTestHooksStatics> dxaml_core_test_hooks_static = get_activation_factory<UWP::IDxamlCoreTestHooksStatics>(name);

							if (dxaml_core_test_hooks_static)
							{
								OutputDebugStringW(
									L"[uwp] dxaml_core_test_hooks_static ok!\n"
								);
							}

							com_ptr<UWP::IDxamlCoreTestHooks> dxaml_core_test_hooks = nullptr;
							check_hresult(
								dxaml_core_test_hooks_static->GetForCurrentThread(dxaml_core_test_hooks.put())
							);
							if (dxaml_core_test_hooks)
							{
								OutputDebugStringW(
									L"[uwp] dxaml_core_test_hooks ok!\n"
								);
							}

							OutputDebugStringW(
								L"[uwp] try GetAllXamlRoots...\n"
							);
							auto xaml_test_hooks = dxaml_core_test_hooks.as<UWP::IXamlTestHooks>();
							IVectorView<XamlRoot> xaml_root_collection = nullptr;
							check_hresult(
								xaml_test_hooks->GetAllXamlRoots(reinterpret_cast<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Xaml::XamlRoot*>**>(put_abi(xaml_root_collection)))
							);

							OutputDebugStringW(
								std::format(
									L"xaml_root_collection size: {}\n",
									xaml_root_collection.Size()
								).c_str()
							);
							for (auto xaml_root : xaml_root_collection)
							{
								OutputDebugStringW(L"[uwp] xaml_root\n");
								try
								{
									OutputDebugStringW(L"[uwp] try walk_visual_tree -> xaml_root.Content()\n");
									auto content = xaml_root.Content();
									if (content)
									{
										auto name = hstring(L"Windows.UI.Xaml.Hosting.XamlIsland");
										com_ptr<UWP::IXamlIslandStatics> dxaml_core_test_hooks_static = get_activation_factory<UWP::IXamlIslandStatics>(name);

										try
										{
											OutputDebugStringW(L"try GetIslandFromElement\n");
											com_ptr<UWP::IXamlIsland> island = nullptr;
											check_hresult(
												dxaml_core_test_hooks_static->GetIslandFromElement(
													content.as<ABI::Windows::UI::Xaml::IDependencyObject>().get(),
													island.put()
												)
											);
											if (!island) throw hresult_class_not_available();

											{
												com_ptr<ABI::Windows::UI::Xaml::IUIElement> content = nullptr;
												check_hresult(
													island->get_Content(content.put())
												);
											}
										}
										catch (...)
										{
											OutputDebugStringW(L"this element has no xaml island...\n");
											OutputDebugStringW(
												to_message().c_str()
											);
										}
									}

									walk_visual_tree(content, [](UIElement element)
									{
										return true;
									});
								}
								catch (...)
								{
									OutputDebugStringW(
										to_message().c_str()
									);
								}
							}
						}
						catch (...)
						{
							OutputDebugStringW(
								to_message().c_str()
							);
						}
					});

					OutputDebugStringW(L"[uwp] try => dispatcher.RunAsync");
					auto async_operation = dispatcher.RunAsync(winrt::Windows::UI::Core::CoreDispatcherPriority::Low, []()
					{
							OutputDebugStringW(L"[uwp] transform_window_mica");
						transform_window_mica();
					});
					if (!async_operation) throw_hresult(E_POINTER);

					//OutputDebugStringW(L"[uwp] try => wait_for_completed");
					//wait_for_completed(async_operation, 0xFFFFFFFF);
				}
				catch (...)
				{
					OutputDebugStringW(L"[uwp] inner catch\n");
					OutputDebugStringW(to_message().c_str());
				}
			}
		}
		catch (...)
		{
			OutputDebugStringW(L"[uwp] outer catch\n");
			OutputDebugStringW(to_message().c_str());
		}
	}
	else
	{
		// hook xaml island
		{
			auto name = hstring(name_of<Microsoft::UI::Xaml::Application>());
			using IApplicationStatics = winrt::impl::abi_t<Microsoft::UI::Xaml::IApplicationStatics>;
			com_ptr<IApplicationStatics> application_statics{ nullptr };
			check_hresult(
				RoGetActivationFactory(*reinterpret_cast<HSTRING*>(&name), guid_of<Microsoft::UI::Xaml::IApplicationStatics>(), application_statics.put_void())
			);

			using IApplication = winrt::impl::abi_t<Microsoft::UI::Xaml::IApplication>;
			com_ptr<IApplication> application{ nullptr };
			HRESULT hr = application_statics->get_Current(application.put_void());

			if (SUCCEEDED(hr) && application)
			{
				auto framework_application = application.as<WinUI::IFrameworkApplicationPrivate>();
			}
		}

		inject_callback_to_thread(get_main_thread_id(), []()
		{
			Microsoft::UI::Xaml::DependencyObject;
			Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread().TryEnqueue(Microsoft::UI::Dispatching::DispatcherQueuePriority::High, []()
			{
				auto app = Microsoft::UI::Xaml::Application::Current().as<WinUI::IFrameworkApplicationPrivate>();
				IVectorView<Microsoft::UI::Xaml::Window> window_collection = nullptr;
				OutputDebugStringW(
					L"[winui] try get_Windows...\n"
				);
				check_hresult(
					app->get_Windows(reinterpret_cast<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Xaml::Window*>**>(put_abi(window_collection)))
				);

				OutputDebugStringW(
					std::format(
						L"window_collection size: {}\n",
						window_collection.Size()
					).c_str()
				);
				try
				{
					for (auto window : window_collection)
					{
						OutputDebugStringW(L"[winui] winui_walk_visual_tree -> window.Content()\n");
						winui_walk_visual_tree(window.Content(), [](Microsoft::UI::Xaml::UIElement element)
						{
							return true;
						});

						auto system_backdrop_configuration = Microsoft::UI::Composition::SystemBackdrops::SystemBackdropConfiguration();
						system_backdrop_configuration.IsInputActive(true);

						auto& acrylic_controller = get_acrylic_controller();
						acrylic_controller.TintOpacity(0.f);
						acrylic_controller.LuminosityOpacity(0.f);
						acrylic_controller.Kind(Microsoft::UI::Composition::SystemBackdrops::DesktopAcrylicKind::Base);
						acrylic_controller.SetSystemBackdropConfiguration(system_backdrop_configuration);
						acrylic_controller.AddSystemBackdropTarget(window.as<Microsoft::UI::Composition::ICompositionSupportsSystemBackdrop>());

						//auto system_backdrop = Microsoft::UI::Xaml::Media::DesktopAcrylicBackdrop();
						window.SystemBackdrop(nullptr);
					}
				}
				catch (...)
				{
					OutputDebugStringW(
						to_message().c_str()
					);
				}

				try
				{
					auto name = hstring(L"Microsoft.UI.Xaml.DxamlCoreTestHooks");
					com_ptr<WinUI::IDxamlCoreTestHooksStatics> dxaml_core_test_hooks_static = get_activation_factory<WinUI::IDxamlCoreTestHooksStatics>(name);

					if (dxaml_core_test_hooks_static)
					{
						OutputDebugStringW(
							L"[winui] dxaml_core_test_hooks_static ok!\n"
						);
					}

					com_ptr<WinUI::IDxamlCoreTestHooks> dxaml_core_test_hooks = nullptr;
					check_hresult(
						dxaml_core_test_hooks_static->GetForCurrentThread(dxaml_core_test_hooks.put())
					);
					if (dxaml_core_test_hooks)
					{
						OutputDebugStringW(
							L"[winui] dxaml_core_test_hooks ok!\n"
						);
					}

					OutputDebugStringW(
						L"[winui] try GetAllXamlRoots...\n"
					);
					auto xaml_test_hooks = dxaml_core_test_hooks.as<WinUI::IXamlTestHooks>();
					IVectorView<Microsoft::UI::Xaml::XamlRoot> xaml_root_collection = nullptr;
					check_hresult(
						xaml_test_hooks->GetAllXamlRoots(reinterpret_cast<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Xaml::XamlRoot*>**>(put_abi(xaml_root_collection)))
					);

					OutputDebugStringW(
						std::format(
							L"xaml_root_collection size: {}\n",
							xaml_root_collection.Size()
						).c_str()
					);
					for (auto xaml_root : xaml_root_collection)
					{
						OutputDebugStringW(L"[winui] xaml_root\n");

						OutputDebugStringW(L"[winui] winui_walk_visual_tree -> xaml_root.Content()\n");
						winui_walk_visual_tree(xaml_root.Content(), [](Microsoft::UI::Xaml::UIElement element)
						{
							return true;
						});
					}
				}
				catch (...)
				{
					OutputDebugStringW(
						to_message().c_str()
					);
				}
			});
		});
	}
}

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD  dwReason,
	LPVOID lpReserved
)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			DisableThreadLibraryCalls(hModule);

			if (!GetModuleHandleW(L"rundll32.exe"))
			{
				std::thread([]
				{
					winrt::init_apartment();
					auto clean_up = std::scope_exit([]
					{
						winrt::uninit_apartment();
					});
					run_callback();
				}).detach();
			}
			break;
		}

		case DLL_PROCESS_DETACH:
		{
			break;
		}
		default:
			break;
	}

	return TRUE;
}

extern "C" __declspec(dllexport) HRESULT install() try
{
	winrt::init_apartment();
	auto clean_up = std::scope_exit([]
	{
		winrt::uninit_apartment();
	});

	{
		com_ptr<ITaskService> task_service{ nullptr };
		check_hresult(
			CoCreateInstance(
				CLSID_TaskScheduler,
				nullptr,
				CLSCTX_INPROC_SERVER,
				IID_PPV_ARGS(task_service.put())
			)
		);

		check_hresult(task_service->Connect(_variant_t{}, _variant_t{}, _variant_t{}, _variant_t{}));

		com_ptr<ITaskFolder> root_folder{ nullptr };
		check_hresult(task_service->GetFolder(_bstr_t("\\"), root_folder.put()));

		com_ptr<ITaskDefinition> task_definition{ nullptr };
		check_hresult(task_service->NewTask(0, task_definition.put()));

		com_ptr<IRegistrationInfo> registration_info{ nullptr };
		check_hresult(task_definition->get_RegistrationInfo(registration_info.put()));
		check_hresult(registration_info->put_Author(const_cast<BSTR>(L"ALTaleX")));
		check_hresult(registration_info->put_Description(const_cast<BSTR>(L"Replace the ugly mica with true acrylic effect.")));

		{
			com_ptr<IPrincipal> principal{ nullptr };
			check_hresult(task_definition->get_Principal(principal.put()));

			check_hresult(principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN));
			check_hresult(principal->put_RunLevel(TASK_RUNLEVEL_LUA));
		}

		{
			com_ptr<ITaskSettings> setting{ nullptr };
			check_hresult(task_definition->get_Settings(setting.put()));

			check_hresult(setting->put_StopIfGoingOnBatteries(VARIANT_FALSE));
			check_hresult(setting->put_DisallowStartIfOnBatteries(VARIANT_FALSE));
			check_hresult(setting->put_AllowDemandStart(VARIANT_TRUE));
			check_hresult(setting->put_StartWhenAvailable(VARIANT_FALSE));
			check_hresult(setting->put_MultipleInstances(TASK_INSTANCES_STOP_EXISTING));
		}

		{
			com_ptr<IExecAction> exec_action{ nullptr };
			{
				com_ptr<IAction> action{ nullptr };
				{
					com_ptr<IActionCollection> actionColl{ nullptr };
					check_hresult(task_definition->get_Actions(actionColl.put()));
					check_hresult(actionColl->Create(TASK_ACTION_EXEC, action.put()));
				}
				action.as(exec_action);
			}

			WCHAR module_path[MAX_PATH + 1] {};
			check_bool(!GetModuleFileName(HINST_THISCOMPONENT, module_path, MAX_PATH));

			check_hresult(
				exec_action->put_Path(
					const_cast<BSTR>(L"Rundll32")
				)
			);

			check_hresult(
				exec_action->put_Arguments(
					const_cast<BSTR>(
						std::format(L"\"{}\",main /start", module_path).c_str()
					)
				)
			);
		}

		com_ptr<ITriggerCollection> trigger_coll{ nullptr };
		check_hresult(task_definition->get_Triggers(trigger_coll.put()));

		com_ptr<ITrigger> trigger{ nullptr };
		check_hresult(trigger_coll->Create(TASK_TRIGGER_LOGON, trigger.put()));

		com_ptr<IRegisteredTask> registered_task{ nullptr };
		check_hresult(
			root_folder->RegisterTaskDefinition(
				const_cast<BSTR>(L"BringMeAcrylic"),
				task_definition.get(),
				TASK_CREATE_OR_UPDATE,
				_variant_t{},
				_variant_t{},
				TASK_LOGON_INTERACTIVE_TOKEN,
				_variant_t{},
				registered_task.put()
			)
		);
	}

	return S_OK;
}
catch (...)
{
	ShellMessageBoxW(
		HINST_THISCOMPONENT,
		nullptr,
		to_message().c_str(),
		nullptr,
		MB_ICONERROR | MB_SYSTEMMODAL
	);
	return to_hresult();
}

extern "C" __declspec(dllexport) HRESULT uninstall() try
{
	winrt::init_apartment();
	auto clean_up = std::scope_exit([]
	{
		winrt::uninit_apartment();
	});

	{
		com_ptr<ITaskService> task_service{ nullptr };
		check_hresult(
			CoCreateInstance(
				CLSID_TaskScheduler,
				nullptr,
				CLSCTX_INPROC_SERVER,
				IID_PPV_ARGS(task_service.put())
			)
		);

		check_hresult(task_service->Connect(_variant_t{}, _variant_t{}, _variant_t{}, _variant_t{}));

		com_ptr<ITaskFolder> root_folder{ nullptr };
		check_hresult(task_service->GetFolder(_bstr_t("\\"), root_folder.put()));

		check_hresult(
			root_folder->DeleteTask(
				const_cast<BSTR>(L"BringMeAcrylic"),
				0
			)
		);
	}

	return S_OK;
}
catch (...)
{
	ShellMessageBoxW(
		HINST_THISCOMPONENT,
		nullptr,
		to_message().c_str(),
		nullptr,
		MB_ICONERROR | MB_SYSTEMMODAL
	);
	return to_hresult();
}

extern "C" __declspec(dllexport) HRESULT stop() try
{
	winrt::init_apartment();
	auto clean_up = std::scope_exit([]
	{
		winrt::uninit_apartment();
	});

	{
		com_ptr<ITaskService> task_service{ nullptr };
		check_hresult(
			CoCreateInstance(
				CLSID_TaskScheduler,
				nullptr,
				CLSCTX_INPROC_SERVER,
				IID_PPV_ARGS(task_service.put())
			)
		);

		check_hresult(task_service->Connect(_variant_t{}, _variant_t{}, _variant_t{}, _variant_t{}));

		com_ptr<ITaskFolder> root_folder{ nullptr };
		check_hresult(task_service->GetFolder(_bstr_t("\\"), root_folder.put()));

		com_ptr<IRegisteredTask> registered_task{nullptr};
		check_hresult(
			root_folder->GetTask(
				const_cast<BSTR>(L"BringMeAcrylic"),
				registered_task.put()
			)
		);

		check_hresult(
			registered_task->Stop(0)
		);
	}

	return S_OK;
}
catch (...)
{
	ShellMessageBoxW(
		HINST_THISCOMPONENT,
		nullptr,
		to_message().c_str(),
		nullptr,
		MB_ICONERROR | MB_SYSTEMMODAL
	);
	return to_hresult();
}

extern "C" __declspec(dllexport) int WINAPI main(
	HWND hWnd,
	HINSTANCE hInstance,
	LPCSTR    lpCmdLine,
	int       nCmdShow
)
{
	if (!_stricmp(lpCmdLine, "/stop"))
	{
		return stop();
	}

	if (!_stricmp(lpCmdLine, "/install"))
	{
		return install();
	}

	if (!_stricmp(lpCmdLine, "/uninstall"))
	{
		return uninstall();
	}

	if (!_stricmp(lpCmdLine, "/start"))
	{
		CHAR dll_path[MAX_PATH + 1] = {};
		try
		{
			check_bool(GetModuleFileNameA(HINST_THISCOMPONENT, dll_path, MAX_PATH) != 0);

			PSECURITY_DESCRIPTOR security_descriptor = nullptr;
			auto clean_up = std::scope_exit([&]
			{
				if (security_descriptor)
				{
					LocalFree(security_descriptor);
				}
			});
			ULONG security_descriptor_length = 0;
			check_bool(
				ConvertStringSecurityDescriptorToSecurityDescriptorA(
					"D:(A;;GRGX;;;S-1-15-2-1)(A;;GRGX;;;S-1-15-2-2)", SDDL_REVISION, &security_descriptor,
					&security_descriptor_length
				)
			);

			PACL dacl = nullptr;
			BOOL present = FALSE, defaulted = FALSE;
			check_bool(
				GetSecurityDescriptorDacl(security_descriptor, &present, &dacl, &defaulted)
			);


			check_win32(
				SetNamedSecurityInfoA(
					dll_path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
					nullptr, dacl, nullptr
				)
			);

			PathRemoveFileSpecA(dll_path);
			SetCurrentDirectoryA(dll_path);
			PathAppendA(dll_path, "config.ini");
			OutputDebugStringA(dll_path);

			check_win32(
				SetNamedSecurityInfoA(
					dll_path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
					nullptr, dacl, nullptr
				)
			);
			check_bool(GetModuleFileNameA(HINST_THISCOMPONENT, dll_path, MAX_PATH) != 0);
		}
		catch (...) {}

		while (true)
		{
			static WCHAR buffer[32768] = {};
			GetPrivateProfileSectionW(
				L"app",
				buffer,
				_countof(buffer),
				get_ini_file_path()
			);

			LPCWSTR process_name = buffer;
			std::vector<std::wstring_view> process_list = {};
			while (!(process_name[0] == '\0' && process_name[1] == '\0'))
			{
				process_list.push_back(process_name);
				process_name += wcslen(process_name) + 1;
			}


			try
			{
				enum_process(
					process_list, [&dll_path](DWORD process_id)
				{
					constexpr auto SE_DEBUG_PRIVILEGE = 0x14;
					static const auto s_pfnRtlAdjustPrivilege = (NTSTATUS(NTAPI*)(int, BOOLEAN, BOOLEAN, PBOOLEAN))GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAdjustPrivilege");
					check_pointer(s_pfnRtlAdjustPrivilege);

					BOOLEAN result = false;
					s_pfnRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, false, &result);

					static const auto s_pfnNtCreateThreadEx = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID))GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
					check_pointer(s_pfnNtCreateThreadEx);

					HANDLE process_handle = nullptr;
					LPVOID remote_address = nullptr;
					HANDLE thread_handle = nullptr;

					try
					{
						process_handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, process_id);
						check_pointer(process_handle);
						auto clean_up = std::scope_exit([&]
							{
								if (process_handle)
								{
									CloseHandle(process_handle);
								}
							});

						if (get_process_module(process_handle, dll_path))
						{
							return;
						}

						// inject
						{
							auto clean_up = std::scope_exit([&]
								{
									if (remote_address)
									{
										VirtualFreeEx(process_handle, remote_address, 0x0, MEM_RELEASE);
									}
									if (thread_handle)
									{
										CloseHandle(thread_handle);
									}
								});

							remote_address = VirtualAllocEx(process_handle, nullptr, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
							check_pointer(remote_address);

							auto startRoutine = reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA);
							check_bool(WriteProcessMemory(process_handle, remote_address, dll_path, strlen(dll_path) + 1, nullptr));

							NTSTATUS ntstatus = s_pfnNtCreateThreadEx(&thread_handle, PROCESS_ALL_ACCESS, nullptr, process_handle, startRoutine, remote_address, 0x0, 0x0, 0x0, 0x0, nullptr);
							check_pointer(thread_handle);

							WaitForSingleObject(thread_handle, 400);
						}
					}
					catch (...)
					{
						OutputDebugStringW(to_message().c_str());
					}

				});
			}
			catch (...) {}

			Sleep(400);
			//DwmFlush();
		}
	}

	return E_ILLEGAL_METHOD_CALL;
}