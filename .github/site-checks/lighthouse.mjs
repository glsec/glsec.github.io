// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Reads Lighthouse JSON reports and fails when a page falls below the
// thresholds (#38). Usage: node lighthouse.mjs report.json...
import { readFileSync } from "node:fs";

const minimum = { accessibility: 100, seo: 100, performance: 90 };

let failed = false;
for (const file of process.argv.slice(2)) {
  const report = JSON.parse(readFileSync(file, "utf8"));
  const scores = Object.entries(minimum).map(([id, min]) => {
    const score = Math.round((report.categories[id]?.score ?? 0) * 100);
    if (score < min) {
      failed = true;
      console.log(`::error::${report.finalDisplayedUrl}: ${id} ${score} < ${min}`);
      for (const ref of report.categories[id]?.auditRefs ?? []) {
        const audit = report.audits[ref.id];
        if (ref.weight > 0 && audit.score !== null && audit.score < 1) {
          console.log(`  ${audit.id}: ${audit.title}`);
        }
      }
    }
    return `${id} ${score}`;
  });
  console.log(`${report.finalDisplayedUrl}: ${scores.join(", ")}`);
}
process.exit(failed ? 1 : 0);
