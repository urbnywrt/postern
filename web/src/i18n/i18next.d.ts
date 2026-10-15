import "i18next";

import type en from "./en.json";
import type insightsEn from "./insights.en.json";

// English is the source of the keys: t("settings.title") is checked against it,
// and a test checks that ru.json has the same ones. insights.en.json holds the
// strings of statistics, diagnostics and the public page under "insights".
declare module "i18next" {
  interface CustomTypeOptions {
    defaultNS: "translation";
    resources: { translation: typeof en & typeof insightsEn };
  }
}
