import { lazy, Suspense } from "react";

import { PageLoader } from "../components/PageLoader";

// The page of a proxy draws a chart, and the chart library is the biggest part of the
// app: the page is loaded when it is first opened, and every other page is not made
// to wait for it.
const ProxyDetail = lazy(() => import("./ProxyDetail").then((module) => ({ default: module.ProxyDetail })));

/** The route of the page of a proxy: it shows a spinner for the moment that the page takes to load. */
export function ProxyDetailRoute() {
  return (
    <Suspense fallback={<PageLoader />}>
      <ProxyDetail />
    </Suspense>
  );
}
