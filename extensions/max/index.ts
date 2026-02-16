import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { maxDock, maxPlugin } from "./src/channel.js";
import { setMaxRuntime } from "./src/runtime.js";

const plugin = {
  id: "max",
  name: "MAX Messenger",
  description: "MAX Messenger channel plugin via official Bot API",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    setMaxRuntime(api.runtime);
    api.registerChannel({ plugin: maxPlugin, dock: maxDock });
  },
};

export default plugin;
