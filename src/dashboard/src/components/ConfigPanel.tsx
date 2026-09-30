import { useEffect, useMemo, useState } from "react";
import { RefreshCw, Save } from "lucide-react";
import {
  fetchTaskTemplatesConfig,
  reloadConfig,
  saveTaskTemplatesConfig,
} from "../api";
import type { TaskTemplatesConfig } from "../types";
import { PanelTitle } from "./CallChainTree";

export function ConfigPanel() {
  const [configText, setConfigText] = useState("");
  const [status, setStatus] = useState("loading");
  const [error, setError] = useState("");

  const summary = useMemo(() => {
    try {
      const parsed = JSON.parse(configText) as TaskTemplatesConfig;
      return `${parsed.templates?.length ?? 0} templates / ${parsed.default_mode ?? "ask"}`;
    } catch {
      return "invalid json";
    }
  }, [configText]);

  useEffect(() => {
    loadConfig();
  }, []);

  async function loadConfig() {
    setStatus("loading");
    setError("");
    try {
      const config = await fetchTaskTemplatesConfig();
      setConfigText(JSON.stringify(config, null, 2));
      setStatus("loaded");
    } catch (err) {
      setError(err instanceof Error ? err.message : "load failed");
      setStatus("failed");
    }
  }

  async function handleSave() {
    setStatus("saving");
    setError("");
    try {
      const parsed = JSON.parse(configText) as TaskTemplatesConfig;
      const result = await saveTaskTemplatesConfig(parsed);
      setStatus(`${result.templates_loaded} templates saved`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "save failed");
      setStatus("failed");
    }
  }

  async function handleReload() {
    setStatus("reloading");
    setError("");
    try {
      const result = await reloadConfig();
      setStatus(`${result.templates_loaded} templates loaded`);
      await loadConfig();
    } catch (err) {
      setError(err instanceof Error ? err.message : "reload failed");
      setStatus("failed");
    }
  }

  return (
    <section className="panel config-panel">
      <PanelTitle title="配置管理" detail={summary} />
      <div className="config-actions">
        <button
          className="tool-button"
          type="button"
          onClick={handleReload}
          disabled={status === "loading" || status === "reloading"}
        >
          <RefreshCw aria-hidden="true" />
          Reload
        </button>
        <button
          className="tool-button primary"
          type="button"
          onClick={handleSave}
          disabled={status === "saving"}
        >
          <Save aria-hidden="true" />
          Save
        </button>
        <span>{status}</span>
      </div>
      <label className="config-editor">
        <span>config/task_templates.json</span>
        <textarea
          value={configText}
          onChange={(event) => setConfigText(event.target.value)}
          spellCheck={false}
          aria-label="Task templates JSON"
        />
      </label>
      {error ? <pre className="config-error">{error}</pre> : null}
    </section>
  );
}
