export type OpenClawButton = {
  type: string;
  text: string;
  data?: string;
  url?: string;
};

export type MaxButton = {
  type: string;
  text: string;
  payload?: string;
  url?: string;
};

export type MaxInlineKeyboardAttachment = {
  type: "inline_keyboard";
  payload: {
    buttons: MaxButton[][];
  };
};

export function mapToMaxButton(btn: OpenClawButton): MaxButton | null {
  switch (btn.type) {
    case "callback":
      return { type: "callback", text: btn.text, payload: btn.data ?? "" };
    case "url":
      return { type: "link", text: btn.text, url: btn.url ?? "" };
    case "contact":
      return { type: "request_contact", text: btn.text };
    case "location":
      return { type: "request_geo_location", text: btn.text };
    default:
      return null;
  }
}

export function buildMaxInlineKeyboard(
  buttons: OpenClawButton[][],
): MaxInlineKeyboardAttachment {
  return {
    type: "inline_keyboard",
    payload: {
      buttons: buttons.map((row) =>
        row.map((btn) => mapToMaxButton(btn)).filter((b): b is MaxButton => b !== null),
      ),
    },
  };
}
