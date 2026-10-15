import { PasswordInput } from "@mantine/core";
import type { ComponentProps } from "react";
import { useTranslation } from "react-i18next";

/**
 * Every password field of the panel. Mantine's own field leaves its show/hide
 * button out of the tab order and hides it from assistive technology unless it
 * is given props, so a keyboard or a screen reader could not reach it. This one
 * names the button (the field says whether the password is shown with
 * `aria-pressed`) and puts it in the tab order. ESLint keeps the raw
 * `PasswordInput` out of the rest of the code.
 */
export function PasswordField(props: ComponentProps<typeof PasswordInput>) {
  const { t } = useTranslation();
  return (
    <PasswordInput
      {...props}
      visibilityToggleButtonProps={{ "aria-label": t("common.showPassword"), tabIndex: 0 }}
    />
  );
}
