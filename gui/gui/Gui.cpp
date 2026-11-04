#include "Gui.h"
#include "Window.h"
#include "AppContext.h"
#include "CEWindow.h"
#include "ServerConnectWindow.h"
#include "ModulesWindow.h"
#include "LogWindow.h"
#include "UxnBreakpointWindow.h"
#include "VersionWindow.h"
#include "ScanWindow.h"
#include "../imgui/imgui.h"
#include "../imgui/imgui_internal.h"
#include <exception>
#include <functional>
#include <map>
#include <thread>
#include <vector>

#ifdef HAVE_LUAJIT
#include "LuaScriptWindow.h"
#endif

namespace Gui {
	std::list<std::unique_ptr<Window>> windows;
	std::list<std::pair<std::string, int>> logs;
	std::mutex logsMutex;

	namespace {
		std::mutex tasksMutex;
		std::vector<std::function<void()>> pendingTasks;
		std::thread::id guiThreadId;
		bool exitRequested = false;

		// 单窗口模式：待切换的 Tab（下一帧生效后清空）。
		std::string requestedTab;

		void runPendingTasks()
		{
			std::vector<std::function<void()>> tasks;
			{
				std::lock_guard<std::mutex> lock(tasksMutex);
				tasks.swap(pendingTasks);
			}
			for (auto& task : tasks) {
				try {
					task();
				} catch (const std::exception& e) {
					Gui::log("GUI任务执行失败: %s", e.what());
				} catch (...) {
					Gui::log("GUI任务执行失败: 未知异常");
				}
			}
		}
	}

	void postTask(std::function<void()> task)
	{
		if (!task)
			return;
		bool runImmediately = false;
		{
			std::lock_guard<std::mutex> lock(tasksMutex);
			runImmediately = guiThreadId != std::thread::id{} &&
				std::this_thread::get_id() == guiThreadId;
			if (!runImmediately) {
				pendingTasks.push_back(std::move(task));
			}
		}
		if (runImmediately) {
			task();
		}
	}

	std::vector<std::pair<std::string, int>> getLogsSnapshot()
	{
		std::lock_guard<std::mutex> lock(logsMutex);
		return {logs.begin(), logs.end()};
	}

	void addWindow(Window* window)
	{
		static std::map<std::string, int> totalWindows;
		if (!window)
			return;

		int& count = totalWindows[window->name];
		if (count > 0) {
			window->name = window->name + " " + std::to_string(count + 1);
		}
		count++;

		windows.emplace_back(window);
	}

	void requestTab(const std::string& name)
	{
		std::lock_guard<std::mutex> lock(tasksMutex);
		requestedTab = name;
	}

	void requestExit()
	{
		exitRequested = true;
	}

	bool mainLoop(Mem::IMemService& service)
	{
		{
			std::lock_guard<std::mutex> lock(tasksMutex);
			guiThreadId = std::this_thread::get_id();
		}
		runPendingTasks();

		static bool bootstrapped = false;
		if (!bootstrapped) {
			if (windows.empty()) {
				Gui::addWindow(new ScanWindow(service));
				Gui::addWindow(new CEWindow(service));
				Gui::addWindow(new ServerConnectWindow(service));
				Gui::addWindow(new ModulesWindow(service));
				Gui::addWindow(new UxnBreakpointWindow(service));
#ifdef HAVE_LUAJIT
				Gui::addWindow(new LuaScriptWindow(service));
#endif
				Gui::addWindow(new LogWindow());
				Gui::addWindow(new VersionWindow(service));
			}
			Gui::log("欢迎使用 MiniMem，请先在「连接」页连上设备");
			Gui::requestTab("内存扫描");
			bootstrapped = true;
		}

		// ── 单窗口布局：一个全屏主窗口 + 顶部 Tab ──
		const ImGuiViewport* viewport = ImGui::GetMainViewport();
		ImGui::SetNextWindowPos(viewport->WorkPos);
		ImGui::SetNextWindowSize(viewport->WorkSize);
		const ImGuiWindowFlags mainFlags =
			ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoBringToFrontOnFocus |
			ImGuiWindowFlags_NoScrollbar;

		ImGui::Begin("MiniMem###MiniMemMain", nullptr, mainFlags);

		// 顶栏：版本与当前目标，便于一眼确认状态
		ImGui::TextUnformatted("MiniMem  Android Memory Debugger");
		ImGui::SameLine();
		ImGui::TextDisabled("|");
		ImGui::SameLine();
		ImGui::Text("PID %d  %s", AppContext::Get().selectedPid.load(),
		            AppContext::Get().getSelectedName().c_str());

		std::string wanted;
		{
			std::lock_guard<std::mutex> lock(tasksMutex);
			wanted = requestedTab;
		}

		// ImGui 的 Tab 在首次提交那一帧可能还没注册，SetSelected 会被默认选中覆盖，
		// 因此切换请求保持若干帧，确保真正生效。
		static std::string lastWanted;
		static int applyFrames = 0;
		if (wanted != lastWanted) {
			lastWanted = wanted;
			applyFrames = 3;
		}
		const bool applyTab = applyFrames > 0;

		if (ImGui::BeginTabBar("##MiniMemMainTabs",
		                       ImGuiTabBarFlags_Reorderable)) {
			for (auto it = windows.begin(); it != windows.end(); ++it) {
				Window* w = it->get();
				if (!w) {
					continue;
				}
				const ImGuiTabItemFlags tabFlags =
					(applyTab && wanted == w->name)
						? ImGuiTabItemFlags_SetSelected
						: ImGuiTabItemFlags_None;
				if (ImGui::BeginTabItem(w->name.c_str(), nullptr, tabFlags)) {
					w->drawInline();
					ImGui::EndTabItem();
				}
			}
			ImGui::EndTabBar();
		}

		ImGui::End();

		if (applyFrames > 0) {
			--applyFrames;
		}

		return !exitRequested;
	}

	void shutdown()
	{
		{
			std::lock_guard<std::mutex> lock(tasksMutex);
			guiThreadId = std::this_thread::get_id();
		}
		runPendingTasks();
		windows.clear();
		// LuaScriptWindow 析构会等待后台脚本退出，期间只能产生最后一批任务。
		runPendingTasks();
		windows.clear();
		std::lock_guard<std::mutex> lock(tasksMutex);
		pendingTasks.clear();
	}
}