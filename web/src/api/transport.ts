import { createConnectTransport } from "@connectrpc/connect-web";

// The panel serves its Connect API (JSON over HTTP/1.1) under /api. The requests
// are same-origin, so the browser sends the HttpOnly session cookie by itself:
// the page never holds a session token.
export const transport = createConnectTransport({ baseUrl: "/api" });
