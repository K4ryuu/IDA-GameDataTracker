/* gamedata_tracker.cpp - plugin entry */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include "tracker.h"

// plugin module
struct gamedata_tracker_plugmod_t : public plugmod_t {

    gamedata_tracker_plugmod_t() {
        msg("GameDataTracker %s loaded\n", K4T_VERSION);
        tracker::auto_load();
    }

    virtual ~gamedata_tracker_plugmod_t() {
        unhook_event_listener(HT_UI, &tracker::g_ui_listener);
        tracker::unregister_actions();

        if (tracker::ui::g_cache.modified && !tracker::ui::g_cache.empty()) {
            msg("GameDataTracker: Warning - unsaved tracking data (%zu functions)\n",
                tracker::ui::g_cache.functions.size());
        }

        msg("GameDataTracker unloaded\n");
    }

    virtual bool idaapi run(size_t arg) override {
        switch (arg) {
            case 0:
                tracker::ui::open_tracked_chooser();
                break;
            case 1:
                tracker::g_action_track.activate(nullptr);
                break;
            case 2:
                tracker::g_action_backtrack.activate(nullptr);
                break;
            case 3:
                tracker::g_action_gensig.activate(nullptr);
                break;
            default:
                tracker::ui::open_tracked_chooser();
                break;
        }
        return true;
    }
};

// init
static plugmod_t* idaapi init() {
    if (!is_idaq()) {
        return nullptr;  // Only GUI version supported
    }

    if (!tracker::register_actions()) {
        msg("GameDataTracker: Failed to register actions\n");
        return nullptr;
    }

    tracker::attach_to_menus();

    hook_event_listener(HT_UI, &tracker::g_ui_listener, nullptr, 0);

    msg("GameDataTracker: Actions registered, UI hooks installed\n");

    return new gamedata_tracker_plugmod_t();
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "GameDataTracker: Modular function tracking across binary versions",
    "Track functions across game updates with signature, string, vtable, and relational matching",
    K4T_NAME,
    nullptr
};
