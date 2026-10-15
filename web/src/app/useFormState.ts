import { useState } from "react";
import { useTranslation } from "react-i18next";

import { type ValidationError, validationMessage } from "./validation";

/** What is wrong with each field of a form, or null (or nothing) for a field that is fine. */
export type FieldErrors<V> = { [K in keyof V]?: ValidationError | null };

/**
 * The state of a form of text fields: the values, and whether a send has been
 * tried. A mistake is pointed out after the first try to send, and then as it is
 * fixed, so that a form that is just opened is not covered in red.
 *
 * The caller works out the mistakes from the values and anything else it knows
 * (the node that a listener belongs to, the listeners that there are), and hands
 * them to `check`, which gives the fields what they need:
 *
 *     const form = useFormState(initial);
 *     const fields = form.check(validate(form.values));
 *     <TextInput {...fields.bind("name")} />
 */
export function useFormState<V extends { [K in keyof V]: string }>(initial: V) {
  const { t } = useTranslation();
  const [values, setValues] = useState<V>(initial);
  const [submitted, setSubmitted] = useState(false);

  const set = (field: keyof V, value: string) => {
    setValues((current) => ({ ...current, [field]: value }));
  };

  const check = (errors: FieldErrors<V>) => {
    const valid = Object.values(errors).every((error) => error === null || error === undefined);

    const errorOf = (field: keyof V): string | undefined =>
      submitted ? validationMessage(t, errors[field] ?? null) : undefined;

    /** For TextInput and Textarea. */
    const bind = (field: keyof V & string) => ({
      value: values[field],
      error: errorOf(field),
      onChange: (event: { currentTarget: { value: string } }) => {
        set(field, event.currentTarget.value);
      },
    });

    /** For Select: the empty string is no choice. */
    const bindSelect = (field: keyof V & string) => ({
      value: values[field] === "" ? null : values[field],
      error: errorOf(field),
      onChange: (value: string | null) => {
        set(field, value ?? "");
      },
    });

    return { valid, errorOf, bind, bindSelect };
  };

  return { values, set, submitted, setSubmitted, check };
}
